/* Header file automatically generated from windows.ui.composition.interactions.idl */
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
#ifndef __windows2Eui2Ecomposition2Einteractions_h__
#define __windows2Eui2Ecomposition2Einteractions_h__
#ifndef __windows2Eui2Ecomposition2Einteractions_p_h__
#define __windows2Eui2Ecomposition2Einteractions_p_h__


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
#include "Windows.UI.Composition.h"
#include "Windows.UI.Input.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface ICompositionConditionalValue;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue ABI::Windows::UI::Composition::Interactions::ICompositionConditionalValue

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface ICompositionConditionalValueStatics;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics ABI::Windows::UI::Composition::Interactions::ICompositionConditionalValueStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface ICompositionInteractionSource;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface ICompositionInteractionSourceCollection;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionSourceConfiguration;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration ABI::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTracker;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker ABI::Windows::UI::Composition::Interactions::IInteractionTracker

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTracker2;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2 ABI::Windows::UI::Composition::Interactions::IInteractionTracker2

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTracker3;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3 ABI::Windows::UI::Composition::Interactions::IInteractionTracker3

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTracker4;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4 ABI::Windows::UI::Composition::Interactions::IInteractionTracker4

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerCustomAnimationStateEnteredArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs ABI::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerCustomAnimationStateEnteredArgs2;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2 ABI::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs2

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerIdleStateEnteredArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs ABI::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerIdleStateEnteredArgs2;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2 ABI::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs2

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInertiaModifier;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInertiaModifierFactory;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifierFactory

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInertiaMotion;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInertiaMotionStatics;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotionStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInertiaNaturalMotion;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInertiaNaturalMotionStatics;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotionStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInertiaRestingValue;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInertiaRestingValueStatics;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValueStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInertiaStateEnteredArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInertiaStateEnteredArgs2;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2 ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs2

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInertiaStateEnteredArgs3;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3 ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs3

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInteractingStateEnteredArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerInteractingStateEnteredArgs2;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2 ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs2

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerOwner;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner ABI::Windows::UI::Composition::Interactions::IInteractionTrackerOwner

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerRequestIgnoredArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs ABI::Windows::UI::Composition::Interactions::IInteractionTrackerRequestIgnoredArgs

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerStatics;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics ABI::Windows::UI::Composition::Interactions::IInteractionTrackerStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerStatics2;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2 ABI::Windows::UI::Composition::Interactions::IInteractionTrackerStatics2

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerValuesChangedArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs ABI::Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerVector2InertiaModifier;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier ABI::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerVector2InertiaModifierFactory;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory ABI::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifierFactory

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerVector2InertiaNaturalMotion;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion ABI::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IInteractionTrackerVector2InertiaNaturalMotionStatics;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics ABI::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotionStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IVisualInteractionSource;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource ABI::Windows::UI::Composition::Interactions::IVisualInteractionSource

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IVisualInteractionSource2;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 ABI::Windows::UI::Composition::Interactions::IVisualInteractionSource2

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IVisualInteractionSource3;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3 ABI::Windows::UI::Composition::Interactions::IVisualInteractionSource3

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IVisualInteractionSourceObjectFactory;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory ABI::Windows::UI::Composition::Interactions::IVisualInteractionSourceObjectFactory

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IVisualInteractionSourceStatics;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics ABI::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    interface IVisualInteractionSourceStatics2;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2 ABI::Windows::UI::Composition::Interactions::IVisualInteractionSourceStatics2

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class CompositionConditionalValue;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_USE
#define DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("8a75b02d-3991-55a6-bfe2-82cb7dd65b98"))
IIterator<ABI::Windows::UI::Composition::Interactions::CompositionConditionalValue*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Interactions::CompositionConditionalValue*, ABI::Windows::UI::Composition::Interactions::ICompositionConditionalValue*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.UI.Composition.Interactions.CompositionConditionalValue>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::UI::Composition::Interactions::CompositionConditionalValue*> __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_t;
#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Interactions::ICompositionConditionalValue*>
//#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Interactions::ICompositionConditionalValue*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_USE
#define DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("b268447b-f519-5ce5-89cd-b7e1bc5652ee"))
IIterable<ABI::Windows::UI::Composition::Interactions::CompositionConditionalValue*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Interactions::CompositionConditionalValue*, ABI::Windows::UI::Composition::Interactions::ICompositionConditionalValue*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.UI.Composition.Interactions.CompositionConditionalValue>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::UI::Composition::Interactions::CompositionConditionalValue*> __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_t;
#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Interactions::ICompositionConditionalValue*>
//#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Interactions::ICompositionConditionalValue*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_USE
#define DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("20259ef3-9f4b-5257-8581-6d3eabbbd690"))
IIterator<ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource*> : IIterator_impl<ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.UI.Composition.Interactions.ICompositionInteractionSource>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource*> __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_t;
#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource*>
//#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_USE
#define DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("17c50e21-cb70-5a2b-b797-a8dc01a99113"))
IIterable<ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource*> : IIterable_impl<ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.UI.Composition.Interactions.ICompositionInteractionSource>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource*> __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_t;
#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource*>
//#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerInertiaModifier;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_USE
#define DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("46617d87-2cd2-5e31-9a30-ea86f8aa7ca1"))
IIterator<ABI::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier*, ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.UI.Composition.Interactions.InteractionTrackerInertiaModifier>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier*> __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_t;
#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier*>
//#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_USE
#define DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("9a245c40-aae6-59fb-87f5-4bb05599f0b1"))
IIterable<ABI::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier*, ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.UI.Composition.Interactions.InteractionTrackerInertiaModifier>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::UI::Composition::Interactions::InteractionTrackerInertiaModifier*> __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_t;
#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier*>
//#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaModifier*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerVector2InertiaModifier;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_USE
#define DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("7762caab-5b42-5958-9f49-06aefd43ad75"))
IIterator<ABI::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier*, ABI::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaModifier>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier*> __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_t;
#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier*>
//#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_USE
#define DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("3aeacfd8-c7f1-580c-a23b-99666e42e62b"))
IIterable<ABI::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier*, ABI::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaModifier>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::UI::Composition::Interactions::InteractionTrackerVector2InertiaModifier*> __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_t;
#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier*>
//#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaModifier*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

namespace ABI {
    namespace Windows {
        namespace Foundation {
            namespace Numerics {
                struct Vector3;
                
            } /* Numerics */
        } /* Foundation */
    } /* Windows */} /* ABI */


#ifndef DEF___FIReference_1_Windows__CFoundation__CNumerics__CVector3_USE
#define DEF___FIReference_1_Windows__CFoundation__CNumerics__CVector3_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("1ee770ff-c954-59ca-a754-6199a9be282c"))
IReference<struct ABI::Windows::Foundation::Numerics::Vector3> : IReference_impl<struct ABI::Windows::Foundation::Numerics::Vector3> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Windows.Foundation.Numerics.Vector3>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<struct ABI::Windows::Foundation::Numerics::Vector3> __FIReference_1_Windows__CFoundation__CNumerics__CVector3_t;
#define __FIReference_1_Windows__CFoundation__CNumerics__CVector3 ABI::Windows::Foundation::__FIReference_1_Windows__CFoundation__CNumerics__CVector3_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_Windows__CFoundation__CNumerics__CVector3 ABI::Windows::Foundation::IReference<ABI::Windows::Foundation::Numerics::Vector3>
//#define __FIReference_1_Windows__CFoundation__CNumerics__CVector3_t ABI::Windows::Foundation::IReference<ABI::Windows::Foundation::Numerics::Vector3>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_Windows__CFoundation__CNumerics__CVector3_USE */




#ifndef DEF___FIReference_1_float_USE
#define DEF___FIReference_1_float_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("719cc2ba-3e76-5def-9f1a-38d85a145ea8"))
IReference<float> : IReference_impl<float> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Single>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<float> __FIReference_1_float_t;
#define __FIReference_1_float ABI::Windows::Foundation::__FIReference_1_float_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_float ABI::Windows::Foundation::IReference<FLOAT>
//#define __FIReference_1_float_t ABI::Windows::Foundation::IReference<FLOAT>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_float_USE */





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
        namespace UI {
            namespace Composition {
                class CompositionAnimation;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CComposition_CICompositionAnimation_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CICompositionAnimation_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                interface ICompositionAnimation;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CICompositionAnimation ABI::Windows::UI::Composition::ICompositionAnimation

#endif // ____x_ABI_CWindows_CUI_CComposition_CICompositionAnimation_FWD_DEFINED__


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


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                class ExpressionAnimation;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                interface IExpressionAnimation;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation ABI::Windows::UI::Composition::IExpressionAnimation

#endif // ____x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                interface IVisualElement;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CIVisualElement ABI::Windows::UI::Composition::IVisualElement

#endif // ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                class ScalarNaturalMotionAnimation;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CComposition_CIScalarNaturalMotionAnimation_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIScalarNaturalMotionAnimation_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                interface IScalarNaturalMotionAnimation;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CIScalarNaturalMotionAnimation ABI::Windows::UI::Composition::IScalarNaturalMotionAnimation

#endif // ____x_ABI_CWindows_CUI_CComposition_CIScalarNaturalMotionAnimation_FWD_DEFINED__


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                class Vector2NaturalMotionAnimation;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CComposition_CIVector2NaturalMotionAnimation_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIVector2NaturalMotionAnimation_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                interface IVector2NaturalMotionAnimation;
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CIVector2NaturalMotionAnimation ABI::Windows::UI::Composition::IVector2NaturalMotionAnimation

#endif // ____x_ABI_CWindows_CUI_CComposition_CIVector2NaturalMotionAnimation_FWD_DEFINED__


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
                class PointerPoint;
            } /* Input */
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CInput_CIPointerPoint_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CInput_CIPointerPoint_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Input {
                interface IPointerPoint;
            } /* Input */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CInput_CIPointerPoint ABI::Windows::UI::Input::IPointerPoint

#endif // ____x_ABI_CWindows_CUI_CInput_CIPointerPoint_FWD_DEFINED__





namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    
                    typedef enum InteractionBindingAxisModes : unsigned int InteractionBindingAxisModes;
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    
                    typedef enum InteractionChainingMode : int InteractionChainingMode;
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    
                    typedef enum InteractionSourceMode : int InteractionSourceMode;
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    
                    typedef enum InteractionSourceRedirectionMode : int InteractionSourceRedirectionMode;
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    
                    typedef enum InteractionTrackerClampingOption : int InteractionTrackerClampingOption;
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    
                    typedef enum VisualInteractionSourceRedirectionMode : int VisualInteractionSourceRedirectionMode;
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */











































namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class CompositionInteractionSourceCollection;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionSourceConfiguration;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTracker;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerCustomAnimationStateEnteredArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerIdleStateEnteredArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerInertiaMotion;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerInertiaNaturalMotion;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerInertiaRestingValue;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerInertiaStateEnteredArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerInteractingStateEnteredArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerRequestIgnoredArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerValuesChangedArgs;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class InteractionTrackerVector2InertiaNaturalMotion;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    class VisualInteractionSource;
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */












/*
 *
 * Struct Windows.UI.Composition.Interactions.InteractionBindingAxisModes
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
                namespace Interactions {
                    /* [v1_enum, flags, contract] */
                    enum InteractionBindingAxisModes : unsigned int
                    {
                        InteractionBindingAxisModes_None = 0,
                        InteractionBindingAxisModes_PositionX = 0x1,
                        InteractionBindingAxisModes_PositionY = 0x2,
                        InteractionBindingAxisModes_Scale = 0x4,
                    };
                    
                    DEFINE_ENUM_FLAG_OPERATORS(InteractionBindingAxisModes)
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.Composition.Interactions.InteractionChainingMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [v1_enum, contract] */
                    enum InteractionChainingMode : int
                    {
                        InteractionChainingMode_Auto = 0,
                        InteractionChainingMode_Always = 1,
                        InteractionChainingMode_Never = 2,
                    };
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.UI.Composition.Interactions.InteractionSourceMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [v1_enum, contract] */
                    enum InteractionSourceMode : int
                    {
                        InteractionSourceMode_Disabled = 0,
                        InteractionSourceMode_EnabledWithInertia = 1,
                        InteractionSourceMode_EnabledWithoutInertia = 2,
                    };
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.UI.Composition.Interactions.InteractionSourceRedirectionMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [v1_enum, contract] */
                    enum InteractionSourceRedirectionMode : int
                    {
                        InteractionSourceRedirectionMode_Disabled = 0,
                        InteractionSourceRedirectionMode_Enabled = 1,
                    };
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.UI.Composition.Interactions.InteractionTrackerClampingOption
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [v1_enum, contract] */
                    enum InteractionTrackerClampingOption : int
                    {
                        InteractionTrackerClampingOption_Auto = 0,
                        InteractionTrackerClampingOption_Disabled = 1,
                    };
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.UI.Composition.Interactions.VisualInteractionSourceRedirectionMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [v1_enum, contract] */
                    enum VisualInteractionSourceRedirectionMode : int
                    {
                        VisualInteractionSourceRedirectionMode_Off = 0,
                        VisualInteractionSourceRedirectionMode_CapableTouchpadOnly = 1,
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
                        
                        VisualInteractionSourceRedirectionMode_PointerWheelOnly = 2,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
                        
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
                        
                        VisualInteractionSourceRedirectionMode_CapableTouchpadAndPointerWheel = 3,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
                        
                    };
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.ICompositionConditionalValue
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.CompositionConditionalValue
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_ICompositionConditionalValue[] = L"Windows.UI.Composition.Interactions.ICompositionConditionalValue";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("43250538-EB73-4561-A71D-1A43EAEB7A9B"), exclusiveto, contract] */
                    MIDL_INTERFACE("43250538-EB73-4561-A71D-1A43EAEB7A9B")
                    ICompositionConditionalValue : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Condition(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::IExpressionAnimation * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Condition(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IExpressionAnimation * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Value(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::IExpressionAnimation * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Value(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IExpressionAnimation * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICompositionConditionalValue=_uuidof(ICompositionConditionalValue);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Composition.Interactions.ICompositionConditionalValueStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.CompositionConditionalValue
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_ICompositionConditionalValueStatics[] = L"Windows.UI.Composition.Interactions.ICompositionConditionalValueStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("090C4B72-8467-4D0A-9065-AC46B80A5522"), exclusiveto, contract] */
                    MIDL_INTERFACE("090C4B72-8467-4D0A-9065-AC46B80A5522")
                    ICompositionConditionalValueStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::ICompositionConditionalValue * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICompositionConditionalValueStatics=_uuidof(ICompositionConditionalValueStatics);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Composition.Interactions.ICompositionInteractionSource
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_ICompositionInteractionSource[] = L"Windows.UI.Composition.Interactions.ICompositionInteractionSource";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("043B2431-06E3-495A-BA54-409F0017FAC0"), contract] */
                    MIDL_INTERFACE("043B2431-06E3-495A-BA54-409F0017FAC0")
                    ICompositionInteractionSource : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICompositionInteractionSource=_uuidof(ICompositionInteractionSource);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.ICompositionInteractionSourceCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.CompositionInteractionSourceCollection
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.Foundation.Collections.IIterable_1_Windows.UI.Composition.Interactions.ICompositionInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_ICompositionInteractionSourceCollection[] = L"Windows.UI.Composition.Interactions.ICompositionInteractionSourceCollection";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("1B468E4B-A5BF-47D8-A547-3894155A158C"), exclusiveto, contract] */
                    MIDL_INTERFACE("1B468E4B-A5BF-47D8-A547-3894155A158C")
                    ICompositionInteractionSourceCollection : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Count(
                            /* [retval, out] */__RPC__out INT32 * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE Add(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE Remove(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSource * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE RemoveAll(void) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICompositionInteractionSourceCollection=_uuidof(ICompositionInteractionSourceCollection);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionSourceConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionSourceConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration[] = L"Windows.UI.Composition.Interactions.IInteractionSourceConfiguration";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("A78347E5-A9D1-4D02-985E-B930CD0B9DA4"), exclusiveto, contract] */
                    MIDL_INTERFACE("A78347E5-A9D1-4D02-985E-B930CD0B9DA4")
                    IInteractionSourceConfiguration : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PositionXSourceMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_PositionXSourceMode(
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PositionYSourceMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_PositionYSourceMode(
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ScaleSourceMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ScaleSourceMode(
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionSourceRedirectionMode value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionSourceConfiguration=_uuidof(IInteractionSourceConfiguration);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTracker
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTracker[] = L"Windows.UI.Composition.Interactions.IInteractionTracker";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("2A8E8CB1-1000-4416-8363-CC27FB877308"), exclusiveto, contract] */
                    MIDL_INTERFACE("2A8E8CB1-1000-4416-8363-CC27FB877308")
                    IInteractionTracker : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_InteractionSources(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::ICompositionInteractionSourceCollection * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsPositionRoundingSuggested(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MaxPosition(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_MaxPosition(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MaxScale(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_MaxScale(
                            /* [in] */FLOAT value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MinPosition(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_MinPosition(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MinScale(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_MinScale(
                            /* [in] */FLOAT value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NaturalRestingPosition(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NaturalRestingScale(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Owner(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerOwner * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Position(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PositionInertiaDecayRate(
                            /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_PositionInertiaDecayRate(
                            /* [in] */__RPC__in_opt __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PositionVelocityInPixelsPerSecond(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Scale(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ScaleInertiaDecayRate(
                            /* [retval, out] */__RPC__deref_out_opt __FIReference_1_float * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ScaleInertiaDecayRate(
                            /* [in] */__RPC__in_opt __FIReference_1_float * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ScaleVelocityInPercentPerSecond(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE AdjustPositionXIfGreaterThanThreshold(
                            /* [in] */FLOAT adjustment,
                            /* [in] */FLOAT positionThreshold
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE AdjustPositionYIfGreaterThanThreshold(
                            /* [in] */FLOAT adjustment,
                            /* [in] */FLOAT positionThreshold
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ConfigurePositionXInertiaModifiers(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * modifiers
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ConfigurePositionYInertiaModifiers(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * modifiers
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ConfigureScaleInertiaModifiers(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * modifiers
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryUpdatePosition(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 value,
                            /* [retval, out] */__RPC__out INT32 * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryUpdatePositionBy(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 amount,
                            /* [retval, out] */__RPC__out INT32 * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryUpdatePositionWithAnimation(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositionAnimation * animation,
                            /* [retval, out] */__RPC__out INT32 * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryUpdatePositionWithAdditionalVelocity(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 velocityInPixelsPerSecond,
                            /* [retval, out] */__RPC__out INT32 * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryUpdateScale(
                            /* [in] */FLOAT value,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 centerPoint,
                            /* [retval, out] */__RPC__out INT32 * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryUpdateScaleWithAnimation(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositionAnimation * animation,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 centerPoint,
                            /* [retval, out] */__RPC__out INT32 * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryUpdateScaleWithAdditionalVelocity(
                            /* [in] */FLOAT velocityInPercentPerSecond,
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 centerPoint,
                            /* [retval, out] */__RPC__out INT32 * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTracker=_uuidof(IInteractionTracker);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTracker2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTracker2[] = L"Windows.UI.Composition.Interactions.IInteractionTracker2";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("25769A3E-CE6D-448C-8386-92620D240756"), exclusiveto, contract] */
                    MIDL_INTERFACE("25769A3E-CE6D-448C-8386-92620D240756")
                    IInteractionTracker2 : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE ConfigureCenterPointXInertiaModifiers(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ConfigureCenterPointYInertiaModifiers(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTracker2=_uuidof(IInteractionTracker2);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTracker3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTracker3[] = L"Windows.UI.Composition.Interactions.IInteractionTracker3";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("E6C5D7A2-5C4B-42C6-84B7-F69441B18091"), exclusiveto, contract] */
                    MIDL_INTERFACE("E6C5D7A2-5C4B-42C6-84B7-F69441B18091")
                    IInteractionTracker3 : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE ConfigureVector2PositionInertiaModifiers(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * modifiers
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTracker3=_uuidof(IInteractionTracker3);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTracker4
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTracker4[] = L"Windows.UI.Composition.Interactions.IInteractionTracker4";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("EBD222BC-04AF-4AC7-847D-06EA36E80A16"), exclusiveto, contract] */
                    MIDL_INTERFACE("EBD222BC-04AF-4AC7-847D-06EA36E80A16")
                    IInteractionTracker4 : public IInspectable
                    {
                    public:
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE TryUpdatePositionWithOption(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 value,
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionTrackerClampingOption option,
                            /* [retval, out] */__RPC__out INT32 * result
                            ) = 0;
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE TryUpdatePositionByWithOption(
                            /* [in] */ABI::Windows::Foundation::Numerics::Vector3 amount,
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionTrackerClampingOption option,
                            /* [retval, out] */__RPC__out INT32 * result
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsInertiaFromImpulse(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTracker4=_uuidof(IInteractionTracker4);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerCustomAnimationStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerCustomAnimationStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("8D1C8CF1-D7B0-434C-A5D2-2D7611864834"), exclusiveto, contract] */
                    MIDL_INTERFACE("8D1C8CF1-D7B0-434C-A5D2-2D7611864834")
                    IInteractionTrackerCustomAnimationStateEnteredArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RequestId(
                            /* [retval, out] */__RPC__out INT32 * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerCustomAnimationStateEnteredArgs=_uuidof(IInteractionTrackerCustomAnimationStateEnteredArgs);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerCustomAnimationStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerCustomAnimationStateEnteredArgs2[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs2";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("47D579B7-0985-5E99-B024-2F32C380C1A4"), exclusiveto, contract] */
                    MIDL_INTERFACE("47D579B7-0985-5E99-B024-2F32C380C1A4")
                    IInteractionTrackerCustomAnimationStateEnteredArgs2 : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsFromBinding(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerCustomAnimationStateEnteredArgs2=_uuidof(IInteractionTrackerCustomAnimationStateEnteredArgs2);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerIdleStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerIdleStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("50012FAA-1510-4142-A1A5-019B09F8857B"), exclusiveto, contract] */
                    MIDL_INTERFACE("50012FAA-1510-4142-A1A5-019B09F8857B")
                    IInteractionTrackerIdleStateEnteredArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RequestId(
                            /* [retval, out] */__RPC__out INT32 * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerIdleStateEnteredArgs=_uuidof(IInteractionTrackerIdleStateEnteredArgs);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerIdleStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerIdleStateEnteredArgs2[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs2";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("F2E771ED-B803-5137-9435-1C96E48721E9"), exclusiveto, contract] */
                    MIDL_INTERFACE("F2E771ED-B803-5137-9435-1C96E48721E9")
                    IInteractionTrackerIdleStateEnteredArgs2 : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsFromBinding(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerIdleStateEnteredArgs2=_uuidof(IInteractionTrackerIdleStateEnteredArgs2);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaModifier
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaModifier
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaModifier[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaModifier";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("A0E2C920-26B4-4DA2-8B61-5E683979BBE2"), exclusiveto, contract] */
                    MIDL_INTERFACE("A0E2C920-26B4-4DA2-8B61-5E683979BBE2")
                    IInteractionTrackerInertiaModifier : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInertiaModifier=_uuidof(IInteractionTrackerInertiaModifier);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaModifierFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaModifier
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaModifierFactory[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaModifierFactory";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("993818FE-C94E-4B86-87F3-922665BA46B9"), exclusiveto, contract] */
                    MIDL_INTERFACE("993818FE-C94E-4B86-87F3-922665BA46B9")
                    IInteractionTrackerInertiaModifierFactory : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInertiaModifierFactory=_uuidof(IInteractionTrackerInertiaModifierFactory);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotion[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotion";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("04922FDC-F154-4CB8-BF33-CC1BA611E6DB"), exclusiveto, contract] */
                    MIDL_INTERFACE("04922FDC-F154-4CB8-BF33-CC1BA611E6DB")
                    IInteractionTrackerInertiaMotion : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Condition(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::IExpressionAnimation * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Condition(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IExpressionAnimation * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Motion(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::IExpressionAnimation * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Motion(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IExpressionAnimation * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInertiaMotion=_uuidof(IInteractionTrackerInertiaMotion);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotionStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotionStatics[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotionStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("8CC83DD6-BA7B-431A-844B-6EAC9130F99A"), exclusiveto, contract] */
                    MIDL_INTERFACE("8CC83DD6-BA7B-431A-844B-6EAC9130F99A")
                    IInteractionTrackerInertiaMotionStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaMotion * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInertiaMotionStatics=_uuidof(IInteractionTrackerInertiaMotionStatics);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaNaturalMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotion[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotion";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("70ACDAAE-27DC-48ED-A3C3-6D61C9A029D2"), exclusiveto, contract] */
                    MIDL_INTERFACE("70ACDAAE-27DC-48ED-A3C3-6D61C9A029D2")
                    IInteractionTrackerInertiaNaturalMotion : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Condition(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::IExpressionAnimation * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Condition(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IExpressionAnimation * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NaturalMotion(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::IScalarNaturalMotionAnimation * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_NaturalMotion(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IScalarNaturalMotionAnimation * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInertiaNaturalMotion=_uuidof(IInteractionTrackerInertiaNaturalMotion);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotionStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaNaturalMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotionStatics[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotionStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("CFDA55B0-5E3E-4289-932D-EE5F50E74283"), exclusiveto, contract] */
                    MIDL_INTERFACE("CFDA55B0-5E3E-4289-932D-EE5F50E74283")
                    IInteractionTrackerInertiaNaturalMotionStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaNaturalMotion * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInertiaNaturalMotionStatics=_uuidof(IInteractionTrackerInertiaNaturalMotionStatics);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValue
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaRestingValue
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValue[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValue";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("86F7EC09-5096-4170-9CC8-DF2FE101BB93"), exclusiveto, contract] */
                    MIDL_INTERFACE("86F7EC09-5096-4170-9CC8-DF2FE101BB93")
                    IInteractionTrackerInertiaRestingValue : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Condition(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::IExpressionAnimation * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Condition(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IExpressionAnimation * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RestingValue(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::IExpressionAnimation * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_RestingValue(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IExpressionAnimation * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInertiaRestingValue=_uuidof(IInteractionTrackerInertiaRestingValue);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValueStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaRestingValue
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValueStatics[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValueStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("18ED4699-0745-4096-BCAB-3A4E99569BCF"), exclusiveto, contract] */
                    MIDL_INTERFACE("18ED4699-0745-4096-BCAB-3A4E99569BCF")
                    IInteractionTrackerInertiaRestingValueStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaRestingValue * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInertiaRestingValueStatics=_uuidof(IInteractionTrackerInertiaRestingValueStatics);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("87108CF2-E7FF-4F7D-9FFD-D72F1E409B63"), exclusiveto, contract] */
                    MIDL_INTERFACE("87108CF2-E7FF-4F7D-9FFD-D72F1E409B63")
                    IInteractionTrackerInertiaStateEnteredArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ModifiedRestingPosition(
                            /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ModifiedRestingScale(
                            /* [retval, out] */__RPC__deref_out_opt __FIReference_1_float * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NaturalRestingPosition(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NaturalRestingScale(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PositionVelocityInPixelsPerSecond(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RequestId(
                            /* [retval, out] */__RPC__out INT32 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ScaleVelocityInPercentPerSecond(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInertiaStateEnteredArgs=_uuidof(IInteractionTrackerInertiaStateEnteredArgs);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs2[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs2";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("B1EB32F6-C26C-41F6-A189-FABC22B323CC"), exclusiveto, contract] */
                    MIDL_INTERFACE("B1EB32F6-C26C-41F6-A189-FABC22B323CC")
                    IInteractionTrackerInertiaStateEnteredArgs2 : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsInertiaFromImpulse(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInertiaStateEnteredArgs2=_uuidof(IInteractionTrackerInertiaStateEnteredArgs2);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs3[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs3";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("48AC1C2F-47BD-59AF-A58C-79BD2EB9EF71"), exclusiveto, contract] */
                    MIDL_INTERFACE("48AC1C2F-47BD-59AF-A58C-79BD2EB9EF71")
                    IInteractionTrackerInertiaStateEnteredArgs3 : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsFromBinding(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInertiaStateEnteredArgs3=_uuidof(IInteractionTrackerInertiaStateEnteredArgs3);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInteractingStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInteractingStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("A7263939-A17B-4011-99FD-B5C24F143748"), exclusiveto, contract] */
                    MIDL_INTERFACE("A7263939-A17B-4011-99FD-B5C24F143748")
                    IInteractionTrackerInteractingStateEnteredArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RequestId(
                            /* [retval, out] */__RPC__out INT32 * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInteractingStateEnteredArgs=_uuidof(IInteractionTrackerInteractingStateEnteredArgs);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInteractingStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInteractingStateEnteredArgs2[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs2";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("509652D6-D488-59CD-819F-F52310295B11"), exclusiveto, contract] */
                    MIDL_INTERFACE("509652D6-D488-59CD-819F-F52310295B11")
                    IInteractionTrackerInteractingStateEnteredArgs2 : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsFromBinding(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerInteractingStateEnteredArgs2=_uuidof(IInteractionTrackerInteractingStateEnteredArgs2);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerOwner
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerOwner[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerOwner";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("DB2E8AF3-4DEB-4E53-B29C-B06C9F96D651"), contract] */
                    MIDL_INTERFACE("DB2E8AF3-4DEB-4E53-B29C-B06C9F96D651")
                    IInteractionTrackerOwner : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE CustomAnimationStateEntered(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * sender,
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerCustomAnimationStateEnteredArgs * args
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE IdleStateEntered(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * sender,
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerIdleStateEnteredArgs * args
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE InertiaStateEntered(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * sender,
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInertiaStateEnteredArgs * args
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE InteractingStateEntered(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * sender,
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerInteractingStateEnteredArgs * args
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE RequestIgnored(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * sender,
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerRequestIgnoredArgs * args
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ValuesChanged(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * sender,
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerValuesChangedArgs * args
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerOwner=_uuidof(IInteractionTrackerOwner);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerRequestIgnoredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerRequestIgnoredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerRequestIgnoredArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerRequestIgnoredArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("80DD82F1-CE25-488F-91DD-CB6455CCFF2E"), exclusiveto, contract] */
                    MIDL_INTERFACE("80DD82F1-CE25-488F-91DD-CB6455CCFF2E")
                    IInteractionTrackerRequestIgnoredArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RequestId(
                            /* [retval, out] */__RPC__out INT32 * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerRequestIgnoredArgs=_uuidof(IInteractionTrackerRequestIgnoredArgs);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerStatics[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("BBA5D7B7-6590-4498-8D6C-EB62B514C92A"), exclusiveto, contract] */
                    MIDL_INTERFACE("BBA5D7B7-6590-4498-8D6C-EB62B514C92A")
                    IInteractionTrackerStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE CreateWithOwner(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerOwner * owner,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerStatics=_uuidof(IInteractionTrackerStatics);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerStatics2[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerStatics2";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("35E53720-46B7-5CB0-B505-F3D6884A6163"), exclusiveto, contract] */
                    MIDL_INTERFACE("35E53720-46B7-5CB0-B505-F3D6884A6163")
                    IInteractionTrackerStatics2 : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE SetBindingMode(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * boundTracker1,
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * boundTracker2,
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionBindingAxisModes axisMode
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE GetBindingMode(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * boundTracker1,
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::Interactions::IInteractionTracker * boundTracker2,
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Interactions::InteractionBindingAxisModes * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerStatics2=_uuidof(IInteractionTrackerStatics2);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerValuesChangedArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerValuesChangedArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerValuesChangedArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerValuesChangedArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("CF1578EF-D3DF-4501-B9E6-F02FB22F73D0"), exclusiveto, contract] */
                    MIDL_INTERFACE("CF1578EF-D3DF-4501-B9E6-F02FB22F73D0")
                    IInteractionTrackerValuesChangedArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Position(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RequestId(
                            /* [retval, out] */__RPC__out INT32 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Scale(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerValuesChangedArgs=_uuidof(IInteractionTrackerValuesChangedArgs);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaModifier
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaModifier
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaModifier[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaModifier";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("87E08AB0-3086-4853-A4B7-77882AD5D7E3"), exclusiveto, contract] */
                    MIDL_INTERFACE("87E08AB0-3086-4853-A4B7-77882AD5D7E3")
                    IInteractionTrackerVector2InertiaModifier : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerVector2InertiaModifier=_uuidof(IInteractionTrackerVector2InertiaModifier);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaModifierFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaModifier
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaModifierFactory[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaModifierFactory";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("7401D6C4-6C6D-48DF-BC3E-171E227E7D7F"), exclusiveto, contract] */
                    MIDL_INTERFACE("7401D6C4-6C6D-48DF-BC3E-171E227E7D7F")
                    IInteractionTrackerVector2InertiaModifierFactory : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerVector2InertiaModifierFactory=_uuidof(IInteractionTrackerVector2InertiaModifierFactory);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaNaturalMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotion[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotion";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("5F17695C-162D-4C07-9400-C282B28276CA"), exclusiveto, contract] */
                    MIDL_INTERFACE("5F17695C-162D-4C07-9400-C282B28276CA")
                    IInteractionTrackerVector2InertiaNaturalMotion : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Condition(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::IExpressionAnimation * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Condition(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IExpressionAnimation * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NaturalMotion(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::IVector2NaturalMotionAnimation * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_NaturalMotion(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IVector2NaturalMotionAnimation * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerVector2InertiaNaturalMotion=_uuidof(IInteractionTrackerVector2InertiaNaturalMotion);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotionStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaNaturalMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotionStatics[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotionStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("82001A48-09C0-434F-8189-141C66DF362F"), exclusiveto, contract] */
                    MIDL_INTERFACE("82001A48-09C0-434F-8189-141C66DF362F")
                    IInteractionTrackerVector2InertiaNaturalMotionStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::IInteractionTrackerVector2InertiaNaturalMotion * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IInteractionTrackerVector2InertiaNaturalMotionStatics=_uuidof(IInteractionTrackerVector2InertiaNaturalMotionStatics);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSource
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSource[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSource";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("CA0E8A86-D8D6-4111-B088-70347BD2B0ED"), exclusiveto, contract] */
                    MIDL_INTERFACE("CA0E8A86-D8D6-4111-B088-70347BD2B0ED")
                    IVisualInteractionSource : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsPositionXRailsEnabled(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsPositionXRailsEnabled(
                            /* [in] */::boolean value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsPositionYRailsEnabled(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsPositionYRailsEnabled(
                            /* [in] */::boolean value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ManipulationRedirectionMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ManipulationRedirectionMode(
                            /* [in] */ABI::Windows::UI::Composition::Interactions::VisualInteractionSourceRedirectionMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PositionXChainingMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Interactions::InteractionChainingMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_PositionXChainingMode(
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionChainingMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PositionXSourceMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Interactions::InteractionSourceMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_PositionXSourceMode(
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionSourceMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PositionYChainingMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Interactions::InteractionChainingMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_PositionYChainingMode(
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionChainingMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PositionYSourceMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Interactions::InteractionSourceMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_PositionYSourceMode(
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionSourceMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ScaleChainingMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Interactions::InteractionChainingMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ScaleChainingMode(
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionChainingMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ScaleSourceMode(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::Composition::Interactions::InteractionSourceMode * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_ScaleSourceMode(
                            /* [in] */ABI::Windows::UI::Composition::Interactions::InteractionSourceMode value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Source(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::IVisual * * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryRedirectForManipulation(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Input::IPointerPoint * pointerPoint
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IVisualInteractionSource=_uuidof(IVisualInteractionSource);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSource2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSource2[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSource2";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("AA914893-A73C-414D-80D0-249BAD2FBD93"), exclusiveto, contract] */
                    MIDL_INTERFACE("AA914893-A73C-414D-80D0-249BAD2FBD93")
                    IVisualInteractionSource2 : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DeltaPosition(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DeltaScale(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Position(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PositionVelocity(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Numerics::Vector3 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Scale(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ScaleVelocity(
                            /* [retval, out] */__RPC__out FLOAT * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ConfigureCenterPointXModifiers(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ConfigureCenterPointYModifiers(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ConfigureDeltaPositionXModifiers(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ConfigureDeltaPositionYModifiers(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ConfigureDeltaScaleModifiers(
                            /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IVisualInteractionSource2=_uuidof(IVisualInteractionSource2);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSource3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSource3[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSource3";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("D941EF2A-0D5C-4057-92D7-C9711533204F"), exclusiveto, contract] */
                    MIDL_INTERFACE("D941EF2A-0D5C-4057-92D7-C9711533204F")
                    IVisualInteractionSource3 : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PointerWheelConfig(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::IInteractionSourceConfiguration * * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IVisualInteractionSource3=_uuidof(IVisualInteractionSource3);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSourceObjectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSourceObjectFactory[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSourceObjectFactory";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("B2CA917C-E98A-41F2-B3C9-891C9266C8F6"), exclusiveto, contract] */
                    MIDL_INTERFACE("B2CA917C-E98A-41F2-B3C9-891C9266C8F6")
                    IVisualInteractionSourceObjectFactory : public IInspectable
                    {
                    public:
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IVisualInteractionSourceObjectFactory=_uuidof(IVisualInteractionSourceObjectFactory);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSourceStatics[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("369965E1-8645-4F75-BA00-6479CD10C8E6"), exclusiveto, contract] */
                    MIDL_INTERFACE("369965E1-8645-4F75-BA00-6479CD10C8E6")
                    IVisualInteractionSourceStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Create(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IVisual * source,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::IVisualInteractionSource * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IVisualInteractionSourceStatics=_uuidof(IVisualInteractionSourceStatics);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSourceStatics2[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics2";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Interactions {
                    /* [object, uuid("A979C032-5764-55E0-BC1F-0778786DCFDE"), exclusiveto, contract] */
                    MIDL_INTERFACE("A979C032-5764-55E0-BC1F-0778786DCFDE")
                    IVisualInteractionSourceStatics2 : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE CreateFromIVisualElement(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IVisualElement * source,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Interactions::IVisualInteractionSource * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IVisualInteractionSourceStatics2=_uuidof(IVisualInteractionSourceStatics2);
                    
                } /* Interactions */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Interactions.CompositionConditionalValue
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.ICompositionConditionalValueStatics interface starting with version 4.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.ICompositionConditionalValue ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_CompositionConditionalValue_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_CompositionConditionalValue_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_CompositionConditionalValue[] = L"Windows.UI.Composition.Interactions.CompositionConditionalValue";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.UI.Composition.Interactions.CompositionInteractionSourceCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.ICompositionInteractionSourceCollection ** Default Interface **
 *    Windows.Foundation.Collections.IIterable_1_Windows.UI.Composition.Interactions.ICompositionInteractionSource
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_CompositionInteractionSourceCollection_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_CompositionInteractionSourceCollection_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_CompositionInteractionSourceCollection[] = L"Windows.UI.Composition.Interactions.CompositionInteractionSourceCollection";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionSourceConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionSourceConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionSourceConfiguration_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionSourceConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionSourceConfiguration[] = L"Windows.UI.Composition.Interactions.InteractionSourceConfiguration";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTracker
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerStatics2 interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerStatics interface starting with version 3.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTracker ** Default Interface **
 *    Windows.UI.Composition.Interactions.IInteractionTracker2
 *    Windows.UI.Composition.Interactions.IInteractionTracker3
 *    Windows.UI.Composition.Interactions.IInteractionTracker4
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTracker_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTracker_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTracker[] = L"Windows.UI.Composition.Interactions.InteractionTracker";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerCustomAnimationStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs ** Default Interface **
 *    Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs2
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerCustomAnimationStateEnteredArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerCustomAnimationStateEnteredArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerCustomAnimationStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerCustomAnimationStateEnteredArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerIdleStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs ** Default Interface **
 *    Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs2
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerIdleStateEnteredArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerIdleStateEnteredArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerIdleStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerIdleStateEnteredArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInertiaModifier
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaModifier ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaModifier_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaModifier_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaModifier[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInertiaModifier";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInertiaMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotionStatics interface starting with version 3.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotion ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaMotion_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaMotion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaMotion[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInertiaMotion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInertiaNaturalMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotionStatics interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotion ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaNaturalMotion_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaNaturalMotion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaNaturalMotion[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInertiaNaturalMotion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInertiaRestingValue
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValueStatics interface starting with version 3.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValue ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaRestingValue_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaRestingValue_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaRestingValue[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInertiaRestingValue";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInertiaStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs ** Default Interface **
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs2
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs3
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaStateEnteredArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaStateEnteredArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInertiaStateEnteredArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInteractingStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs ** Default Interface **
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs2
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInteractingStateEnteredArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInteractingStateEnteredArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInteractingStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInteractingStateEnteredArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerRequestIgnoredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerRequestIgnoredArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerRequestIgnoredArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerRequestIgnoredArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerRequestIgnoredArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerRequestIgnoredArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerValuesChangedArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerValuesChangedArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerValuesChangedArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerValuesChangedArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerValuesChangedArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerValuesChangedArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaModifier
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaModifier ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaModifier_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaModifier_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaModifier[] = L"Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaModifier";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaNaturalMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotionStatics interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotion ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaNaturalMotion_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaNaturalMotion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaNaturalMotion[] = L"Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaNaturalMotion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics2 interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics interface starting with version 3.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IVisualInteractionSource ** Default Interface **
 *    Windows.UI.Composition.Interactions.IVisualInteractionSource2
 *    Windows.UI.Composition.Interactions.IVisualInteractionSource3
 *    Windows.UI.Composition.Interactions.ICompositionInteractionSource
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_VisualInteractionSource_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_VisualInteractionSource_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_VisualInteractionSource[] = L"Windows.UI.Composition.Interactions.VisualInteractionSource";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000





#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2 __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2;

#endif // ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue;

typedef struct __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValueVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValueVtbl;

interface __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue
{
    CONST_VTBL struct __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValueVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue;

typedef  struct __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValueVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue **first);

    END_INTERFACE
} __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValueVtbl;

interface __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue
{
    CONST_VTBL struct __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValueVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource;

typedef struct __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSourceVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSourceVtbl;

interface __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource
{
    CONST_VTBL struct __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSourceVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource;

typedef  struct __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSourceVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource **first);

    END_INTERFACE
} __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSourceVtbl;

interface __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource
{
    CONST_VTBL struct __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSourceVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CUI__CComposition__CInteractions__CICompositionInteractionSource_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier;

typedef struct __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifierVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifierVtbl;

interface __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier
{
    CONST_VTBL struct __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifierVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier;

typedef  struct __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifierVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier **first);

    END_INTERFACE
} __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifierVtbl;

interface __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier
{
    CONST_VTBL struct __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifierVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier;

typedef struct __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifierVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifierVtbl;

interface __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier
{
    CONST_VTBL struct __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifierVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier;

typedef  struct __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifierVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier **first);

    END_INTERFACE
} __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifierVtbl;

interface __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier
{
    CONST_VTBL struct __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifierVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

struct __x_ABI_CWindows_CFoundation_CNumerics_CVector3;

#if !defined(____FIReference_1_Windows__CFoundation__CNumerics__CVector3_INTERFACE_DEFINED__)
#define ____FIReference_1_Windows__CFoundation__CNumerics__CVector3_INTERFACE_DEFINED__

typedef interface __FIReference_1_Windows__CFoundation__CNumerics__CVector3 __FIReference_1_Windows__CFoundation__CNumerics__CVector3;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_Windows__CFoundation__CNumerics__CVector3;

typedef struct __FIReference_1_Windows__CFoundation__CNumerics__CVector3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * This, /* [retval][out] */ __RPC__out struct __x_ABI_CWindows_CFoundation_CNumerics_CVector3 *value);
    END_INTERFACE
} __FIReference_1_Windows__CFoundation__CNumerics__CVector3Vtbl;

interface __FIReference_1_Windows__CFoundation__CNumerics__CVector3
{
    CONST_VTBL struct __FIReference_1_Windows__CFoundation__CNumerics__CVector3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_Windows__CFoundation__CNumerics__CVector3_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_Windows__CFoundation__CNumerics__CVector3_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_Windows__CFoundation__CNumerics__CVector3_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_Windows__CFoundation__CNumerics__CVector3_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_Windows__CFoundation__CNumerics__CVector3_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_Windows__CFoundation__CNumerics__CVector3_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_Windows__CFoundation__CNumerics__CVector3_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_Windows__CFoundation__CNumerics__CVector3_INTERFACE_DEFINED__


#if !defined(____FIReference_1_float_INTERFACE_DEFINED__)
#define ____FIReference_1_float_INTERFACE_DEFINED__

typedef interface __FIReference_1_float __FIReference_1_float;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_float;

typedef struct __FIReference_1_floatVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_float * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_float * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_float * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_float * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_float * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_float * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_float * This, /* [retval][out] */ __RPC__out float *value);
    END_INTERFACE
} __FIReference_1_floatVtbl;

interface __FIReference_1_float
{
    CONST_VTBL struct __FIReference_1_floatVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_float_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_float_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_float_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_float_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_float_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_float_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_float_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_float_INTERFACE_DEFINED__




typedef struct __x_ABI_CWindows_CFoundation_CNumerics_CVector3 __x_ABI_CWindows_CFoundation_CNumerics_CVector3;







#ifndef ____x_ABI_CWindows_CUI_CComposition_CICompositionAnimation_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CICompositionAnimation_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CICompositionAnimation __x_ABI_CWindows_CUI_CComposition_CICompositionAnimation;

#endif // ____x_ABI_CWindows_CUI_CComposition_CICompositionAnimation_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CICompositor __x_ABI_CWindows_CUI_CComposition_CICompositor;

#endif // ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation;

#endif // ____x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CIVisualElement __x_ABI_CWindows_CUI_CComposition_CIVisualElement;

#endif // ____x_ABI_CWindows_CUI_CComposition_CIVisualElement_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CComposition_CIScalarNaturalMotionAnimation_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIScalarNaturalMotionAnimation_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CIScalarNaturalMotionAnimation __x_ABI_CWindows_CUI_CComposition_CIScalarNaturalMotionAnimation;

#endif // ____x_ABI_CWindows_CUI_CComposition_CIScalarNaturalMotionAnimation_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CComposition_CIVector2NaturalMotionAnimation_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIVector2NaturalMotionAnimation_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CIVector2NaturalMotionAnimation __x_ABI_CWindows_CUI_CComposition_CIVector2NaturalMotionAnimation;

#endif // ____x_ABI_CWindows_CUI_CComposition_CIVector2NaturalMotionAnimation_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CIVisual __x_ABI_CWindows_CUI_CComposition_CIVisual;

#endif // ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__





#ifndef ____x_ABI_CWindows_CUI_CInput_CIPointerPoint_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CInput_CIPointerPoint_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CInput_CIPointerPoint __x_ABI_CWindows_CUI_CInput_CIPointerPoint;

#endif // ____x_ABI_CWindows_CUI_CInput_CIPointerPoint_FWD_DEFINED__






typedef enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionBindingAxisModes __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionBindingAxisModes;


typedef enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionChainingMode __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionChainingMode;


typedef enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceMode __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceMode;


typedef enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceRedirectionMode __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceRedirectionMode;


typedef enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionTrackerClampingOption __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionTrackerClampingOption;


typedef enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CVisualInteractionSourceRedirectionMode __x_ABI_CWindows_CUI_CComposition_CInteractions_CVisualInteractionSourceRedirectionMode;





































































/*
 *
 * Struct Windows.UI.Composition.Interactions.InteractionBindingAxisModes
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
/* [v1_enum, flags, contract] */
enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionBindingAxisModes
{
    InteractionBindingAxisModes_None = 0,
    InteractionBindingAxisModes_PositionX = 0x1,
    InteractionBindingAxisModes_PositionY = 0x2,
    InteractionBindingAxisModes_Scale = 0x4,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Struct Windows.UI.Composition.Interactions.InteractionChainingMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionChainingMode
{
    InteractionChainingMode_Auto = 0,
    InteractionChainingMode_Always = 1,
    InteractionChainingMode_Never = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.UI.Composition.Interactions.InteractionSourceMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceMode
{
    InteractionSourceMode_Disabled = 0,
    InteractionSourceMode_EnabledWithInertia = 1,
    InteractionSourceMode_EnabledWithoutInertia = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Struct Windows.UI.Composition.Interactions.InteractionSourceRedirectionMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceRedirectionMode
{
    InteractionSourceRedirectionMode_Disabled = 0,
    InteractionSourceRedirectionMode_Enabled = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.UI.Composition.Interactions.InteractionTrackerClampingOption
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionTrackerClampingOption
{
    InteractionTrackerClampingOption_Auto = 0,
    InteractionTrackerClampingOption_Disabled = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.UI.Composition.Interactions.VisualInteractionSourceRedirectionMode
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CComposition_CInteractions_CVisualInteractionSourceRedirectionMode
{
    VisualInteractionSourceRedirectionMode_Off = 0,
    VisualInteractionSourceRedirectionMode_CapableTouchpadOnly = 1,
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
    
    VisualInteractionSourceRedirectionMode_PointerWheelOnly = 2,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
    
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
    
    VisualInteractionSourceRedirectionMode_CapableTouchpadAndPointerWheel = 3,
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
    
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.ICompositionConditionalValue
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.CompositionConditionalValue
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_ICompositionConditionalValue[] = L"Windows.UI.Composition.Interactions.ICompositionConditionalValue";
/* [object, uuid("43250538-EB73-4561-A71D-1A43EAEB7A9B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Condition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Condition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Value )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Value )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_get_Condition(This,value) \
    ( (This)->lpVtbl->get_Condition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_put_Condition(This,value) \
    ( (This)->lpVtbl->put_Condition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_get_Value(This,value) \
    ( (This)->lpVtbl->get_Value(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_put_Value(This,value) \
    ( (This)->lpVtbl->put_Value(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Composition.Interactions.ICompositionConditionalValueStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.CompositionConditionalValue
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_ICompositionConditionalValueStatics[] = L"Windows.UI.Composition.Interactions.ICompositionConditionalValueStatics";
/* [object, uuid("090C4B72-8467-4D0A-9065-AC46B80A5522"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValue * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionConditionalValueStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Composition.Interactions.ICompositionInteractionSource
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_ICompositionInteractionSource[] = L"Windows.UI.Composition.Interactions.ICompositionInteractionSource";
/* [object, uuid("043B2431-06E3-495A-BA54-409F0017FAC0"), contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.ICompositionInteractionSourceCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.CompositionInteractionSourceCollection
 *
 *
 * Any object which implements this interface must also implement the following interfaces:
 *     Windows.Foundation.Collections.IIterable_1_Windows.UI.Composition.Interactions.ICompositionInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_ICompositionInteractionSourceCollection[] = L"Windows.UI.Composition.Interactions.ICompositionInteractionSourceCollection";
/* [object, uuid("1B468E4B-A5BF-47D8-A547-3894155A158C"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollectionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Count )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    HRESULT ( STDMETHODCALLTYPE *Add )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource * value
        );
    HRESULT ( STDMETHODCALLTYPE *Remove )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSource * value
        );
    HRESULT ( STDMETHODCALLTYPE *RemoveAll )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollectionVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollectionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_get_Count(This,value) \
    ( (This)->lpVtbl->get_Count(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_Add(This,value) \
    ( (This)->lpVtbl->Add(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_Remove(This,value) \
    ( (This)->lpVtbl->Remove(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_RemoveAll(This) \
    ( (This)->lpVtbl->RemoveAll(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionSourceConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionSourceConfiguration
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionSourceConfiguration[] = L"Windows.UI.Composition.Interactions.IInteractionSourceConfiguration";
/* [object, uuid("A78347E5-A9D1-4D02-985E-B930CD0B9DA4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfigurationVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PositionXSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceRedirectionMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_PositionXSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceRedirectionMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PositionYSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceRedirectionMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_PositionYSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceRedirectionMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ScaleSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceRedirectionMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ScaleSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceRedirectionMode value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfigurationVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfigurationVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_get_PositionXSourceMode(This,value) \
    ( (This)->lpVtbl->get_PositionXSourceMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_put_PositionXSourceMode(This,value) \
    ( (This)->lpVtbl->put_PositionXSourceMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_get_PositionYSourceMode(This,value) \
    ( (This)->lpVtbl->get_PositionYSourceMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_put_PositionYSourceMode(This,value) \
    ( (This)->lpVtbl->put_PositionYSourceMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_get_ScaleSourceMode(This,value) \
    ( (This)->lpVtbl->get_ScaleSourceMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_put_ScaleSourceMode(This,value) \
    ( (This)->lpVtbl->put_ScaleSourceMode(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTracker
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTracker[] = L"Windows.UI.Composition.Interactions.IInteractionTracker";
/* [object, uuid("2A8E8CB1-1000-4416-8363-CC27FB877308"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_InteractionSources )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CICompositionInteractionSourceCollection * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsPositionRoundingSuggested )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MaxPosition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_MaxPosition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MaxScale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_MaxScale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */FLOAT value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MinPosition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_MinPosition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MinScale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_MinScale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */FLOAT value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NaturalRestingPosition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NaturalRestingScale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Owner )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Position )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PositionInertiaDecayRate )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_PositionInertiaDecayRate )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__RPC__in_opt __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PositionVelocityInPixelsPerSecond )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Scale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ScaleInertiaDecayRate )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_float * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ScaleInertiaDecayRate )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__RPC__in_opt __FIReference_1_float * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ScaleVelocityInPercentPerSecond )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    HRESULT ( STDMETHODCALLTYPE *AdjustPositionXIfGreaterThanThreshold )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */FLOAT adjustment,
        /* [in] */FLOAT positionThreshold
        );
    HRESULT ( STDMETHODCALLTYPE *AdjustPositionYIfGreaterThanThreshold )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */FLOAT adjustment,
        /* [in] */FLOAT positionThreshold
        );
    HRESULT ( STDMETHODCALLTYPE *ConfigurePositionXInertiaModifiers )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * modifiers
        );
    HRESULT ( STDMETHODCALLTYPE *ConfigurePositionYInertiaModifiers )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * modifiers
        );
    HRESULT ( STDMETHODCALLTYPE *ConfigureScaleInertiaModifiers )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerInertiaModifier * modifiers
        );
    HRESULT ( STDMETHODCALLTYPE *TryUpdatePosition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 value,
        /* [retval, out] */__RPC__out INT32 * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryUpdatePositionBy )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 amount,
        /* [retval, out] */__RPC__out INT32 * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryUpdatePositionWithAnimation )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositionAnimation * animation,
        /* [retval, out] */__RPC__out INT32 * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryUpdatePositionWithAdditionalVelocity )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 velocityInPixelsPerSecond,
        /* [retval, out] */__RPC__out INT32 * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryUpdateScale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */FLOAT value,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 centerPoint,
        /* [retval, out] */__RPC__out INT32 * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryUpdateScaleWithAnimation )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositionAnimation * animation,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 centerPoint,
        /* [retval, out] */__RPC__out INT32 * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryUpdateScaleWithAdditionalVelocity )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * This,
        /* [in] */FLOAT velocityInPercentPerSecond,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 centerPoint,
        /* [retval, out] */__RPC__out INT32 * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_InteractionSources(This,value) \
    ( (This)->lpVtbl->get_InteractionSources(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_IsPositionRoundingSuggested(This,value) \
    ( (This)->lpVtbl->get_IsPositionRoundingSuggested(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_MaxPosition(This,value) \
    ( (This)->lpVtbl->get_MaxPosition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_put_MaxPosition(This,value) \
    ( (This)->lpVtbl->put_MaxPosition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_MaxScale(This,value) \
    ( (This)->lpVtbl->get_MaxScale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_put_MaxScale(This,value) \
    ( (This)->lpVtbl->put_MaxScale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_MinPosition(This,value) \
    ( (This)->lpVtbl->get_MinPosition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_put_MinPosition(This,value) \
    ( (This)->lpVtbl->put_MinPosition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_MinScale(This,value) \
    ( (This)->lpVtbl->get_MinScale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_put_MinScale(This,value) \
    ( (This)->lpVtbl->put_MinScale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_NaturalRestingPosition(This,value) \
    ( (This)->lpVtbl->get_NaturalRestingPosition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_NaturalRestingScale(This,value) \
    ( (This)->lpVtbl->get_NaturalRestingScale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_Owner(This,value) \
    ( (This)->lpVtbl->get_Owner(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_Position(This,value) \
    ( (This)->lpVtbl->get_Position(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_PositionInertiaDecayRate(This,value) \
    ( (This)->lpVtbl->get_PositionInertiaDecayRate(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_put_PositionInertiaDecayRate(This,value) \
    ( (This)->lpVtbl->put_PositionInertiaDecayRate(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_PositionVelocityInPixelsPerSecond(This,value) \
    ( (This)->lpVtbl->get_PositionVelocityInPixelsPerSecond(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_Scale(This,value) \
    ( (This)->lpVtbl->get_Scale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_ScaleInertiaDecayRate(This,value) \
    ( (This)->lpVtbl->get_ScaleInertiaDecayRate(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_put_ScaleInertiaDecayRate(This,value) \
    ( (This)->lpVtbl->put_ScaleInertiaDecayRate(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_get_ScaleVelocityInPercentPerSecond(This,value) \
    ( (This)->lpVtbl->get_ScaleVelocityInPercentPerSecond(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_AdjustPositionXIfGreaterThanThreshold(This,adjustment,positionThreshold) \
    ( (This)->lpVtbl->AdjustPositionXIfGreaterThanThreshold(This,adjustment,positionThreshold) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_AdjustPositionYIfGreaterThanThreshold(This,adjustment,positionThreshold) \
    ( (This)->lpVtbl->AdjustPositionYIfGreaterThanThreshold(This,adjustment,positionThreshold) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_ConfigurePositionXInertiaModifiers(This,modifiers) \
    ( (This)->lpVtbl->ConfigurePositionXInertiaModifiers(This,modifiers) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_ConfigurePositionYInertiaModifiers(This,modifiers) \
    ( (This)->lpVtbl->ConfigurePositionYInertiaModifiers(This,modifiers) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_ConfigureScaleInertiaModifiers(This,modifiers) \
    ( (This)->lpVtbl->ConfigureScaleInertiaModifiers(This,modifiers) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_TryUpdatePosition(This,value,result) \
    ( (This)->lpVtbl->TryUpdatePosition(This,value,result) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_TryUpdatePositionBy(This,amount,result) \
    ( (This)->lpVtbl->TryUpdatePositionBy(This,amount,result) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_TryUpdatePositionWithAnimation(This,animation,result) \
    ( (This)->lpVtbl->TryUpdatePositionWithAnimation(This,animation,result) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_TryUpdatePositionWithAdditionalVelocity(This,velocityInPixelsPerSecond,result) \
    ( (This)->lpVtbl->TryUpdatePositionWithAdditionalVelocity(This,velocityInPixelsPerSecond,result) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_TryUpdateScale(This,value,centerPoint,result) \
    ( (This)->lpVtbl->TryUpdateScale(This,value,centerPoint,result) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_TryUpdateScaleWithAnimation(This,animation,centerPoint,result) \
    ( (This)->lpVtbl->TryUpdateScaleWithAnimation(This,animation,centerPoint,result) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_TryUpdateScaleWithAdditionalVelocity(This,velocityInPercentPerSecond,centerPoint,result) \
    ( (This)->lpVtbl->TryUpdateScaleWithAdditionalVelocity(This,velocityInPercentPerSecond,centerPoint,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTracker2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTracker2[] = L"Windows.UI.Composition.Interactions.IInteractionTracker2";
/* [object, uuid("25769A3E-CE6D-448C-8386-92620D240756"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *ConfigureCenterPointXInertiaModifiers )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
        );
    HRESULT ( STDMETHODCALLTYPE *ConfigureCenterPointYInertiaModifiers )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_ConfigureCenterPointXInertiaModifiers(This,conditionalValues) \
    ( (This)->lpVtbl->ConfigureCenterPointXInertiaModifiers(This,conditionalValues) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_ConfigureCenterPointYInertiaModifiers(This,conditionalValues) \
    ( (This)->lpVtbl->ConfigureCenterPointYInertiaModifiers(This,conditionalValues) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTracker3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTracker3[] = L"Windows.UI.Composition.Interactions.IInteractionTracker3";
/* [object, uuid("E6C5D7A2-5C4B-42C6-84B7-F69441B18091"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *ConfigureVector2PositionInertiaModifiers )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CInteractionTrackerVector2InertiaModifier * modifiers
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_ConfigureVector2PositionInertiaModifiers(This,modifiers) \
    ( (This)->lpVtbl->ConfigureVector2PositionInertiaModifiers(This,modifiers) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTracker4
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTracker4[] = L"Windows.UI.Composition.Interactions.IInteractionTracker4";
/* [object, uuid("EBD222BC-04AF-4AC7-847D-06EA36E80A16"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *TryUpdatePositionWithOption )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4 * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 value,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionTrackerClampingOption option,
        /* [retval, out] */__RPC__out INT32 * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *TryUpdatePositionByWithOption )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4 * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CNumerics_CVector3 amount,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionTrackerClampingOption option,
        /* [retval, out] */__RPC__out INT32 * result
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsInertiaFromImpulse )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4 * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_TryUpdatePositionWithOption(This,value,option,result) \
    ( (This)->lpVtbl->TryUpdatePositionWithOption(This,value,option,result) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_TryUpdatePositionByWithOption(This,amount,option,result) \
    ( (This)->lpVtbl->TryUpdatePositionByWithOption(This,amount,option,result) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_get_IsInertiaFromImpulse(This,value) \
    ( (This)->lpVtbl->get_IsInertiaFromImpulse(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker4_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerCustomAnimationStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerCustomAnimationStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs";
/* [object, uuid("8D1C8CF1-D7B0-434C-A5D2-2D7611864834"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RequestId )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_get_RequestId(This,value) \
    ( (This)->lpVtbl->get_RequestId(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerCustomAnimationStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerCustomAnimationStateEnteredArgs2[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs2";
/* [object, uuid("47D579B7-0985-5E99-B024-2F32C380C1A4"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsFromBinding )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2 * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_get_IsFromBinding(This,value) \
    ( (This)->lpVtbl->get_IsFromBinding(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerIdleStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerIdleStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs";
/* [object, uuid("50012FAA-1510-4142-A1A5-019B09F8857B"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RequestId )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_get_RequestId(This,value) \
    ( (This)->lpVtbl->get_RequestId(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerIdleStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerIdleStateEnteredArgs2[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs2";
/* [object, uuid("F2E771ED-B803-5137-9435-1C96E48721E9"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsFromBinding )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2 * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_get_IsFromBinding(This,value) \
    ( (This)->lpVtbl->get_IsFromBinding(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaModifier
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaModifier
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaModifier[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaModifier";
/* [object, uuid("A0E2C920-26B4-4DA2-8B61-5E683979BBE2"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifier_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaModifierFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaModifier
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaModifierFactory[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaModifierFactory";
/* [object, uuid("993818FE-C94E-4B86-87F3-922665BA46B9"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactoryVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaModifierFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotion[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotion";
/* [object, uuid("04922FDC-F154-4CB8-BF33-CC1BA611E6DB"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Condition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Condition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Motion )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Motion )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_get_Condition(This,value) \
    ( (This)->lpVtbl->get_Condition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_put_Condition(This,value) \
    ( (This)->lpVtbl->put_Condition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_get_Motion(This,value) \
    ( (This)->lpVtbl->get_Motion(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_put_Motion(This,value) \
    ( (This)->lpVtbl->put_Motion(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotionStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaMotionStatics[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotionStatics";
/* [object, uuid("8CC83DD6-BA7B-431A-844B-6EAC9130F99A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotion * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaMotionStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaNaturalMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotion[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotion";
/* [object, uuid("70ACDAAE-27DC-48ED-A3C3-6D61C9A029D2"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Condition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Condition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NaturalMotion )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIScalarNaturalMotionAnimation * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_NaturalMotion )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIScalarNaturalMotionAnimation * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_get_Condition(This,value) \
    ( (This)->lpVtbl->get_Condition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_put_Condition(This,value) \
    ( (This)->lpVtbl->put_Condition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_get_NaturalMotion(This,value) \
    ( (This)->lpVtbl->get_NaturalMotion(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_put_NaturalMotion(This,value) \
    ( (This)->lpVtbl->put_NaturalMotion(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotionStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaNaturalMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaNaturalMotionStatics[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotionStatics";
/* [object, uuid("CFDA55B0-5E3E-4289-932D-EE5F50E74283"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotion * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaNaturalMotionStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValue
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaRestingValue
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValue[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValue";
/* [object, uuid("86F7EC09-5096-4170-9CC8-DF2FE101BB93"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Condition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Condition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RestingValue )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_RestingValue )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_get_Condition(This,value) \
    ( (This)->lpVtbl->get_Condition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_put_Condition(This,value) \
    ( (This)->lpVtbl->put_Condition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_get_RestingValue(This,value) \
    ( (This)->lpVtbl->get_RestingValue(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_put_RestingValue(This,value) \
    ( (This)->lpVtbl->put_RestingValue(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValueStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaRestingValue
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaRestingValueStatics[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValueStatics";
/* [object, uuid("18ED4699-0745-4096-BCAB-3A4E99569BCF"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValue * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaRestingValueStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs";
/* [object, uuid("87108CF2-E7FF-4F7D-9FFD-D72F1E409B63"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ModifiedRestingPosition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CNumerics__CVector3 * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ModifiedRestingScale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_float * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NaturalRestingPosition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NaturalRestingScale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PositionVelocityInPixelsPerSecond )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RequestId )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ScaleVelocityInPercentPerSecond )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_get_ModifiedRestingPosition(This,value) \
    ( (This)->lpVtbl->get_ModifiedRestingPosition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_get_ModifiedRestingScale(This,value) \
    ( (This)->lpVtbl->get_ModifiedRestingScale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_get_NaturalRestingPosition(This,value) \
    ( (This)->lpVtbl->get_NaturalRestingPosition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_get_NaturalRestingScale(This,value) \
    ( (This)->lpVtbl->get_NaturalRestingScale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_get_PositionVelocityInPixelsPerSecond(This,value) \
    ( (This)->lpVtbl->get_PositionVelocityInPixelsPerSecond(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_get_RequestId(This,value) \
    ( (This)->lpVtbl->get_RequestId(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_get_ScaleVelocityInPercentPerSecond(This,value) \
    ( (This)->lpVtbl->get_ScaleVelocityInPercentPerSecond(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs2[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs2";
/* [object, uuid("B1EB32F6-C26C-41F6-A189-FABC22B323CC"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsInertiaFromImpulse )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2 * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_get_IsInertiaFromImpulse(This,value) \
    ( (This)->lpVtbl->get_IsInertiaFromImpulse(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInertiaStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInertiaStateEnteredArgs3[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs3";
/* [object, uuid("48AC1C2F-47BD-59AF-A58C-79BD2EB9EF71"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsFromBinding )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3 * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_get_IsFromBinding(This,value) \
    ( (This)->lpVtbl->get_IsFromBinding(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInteractingStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInteractingStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs";
/* [object, uuid("A7263939-A17B-4011-99FD-B5C24F143748"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RequestId )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_get_RequestId(This,value) \
    ( (This)->lpVtbl->get_RequestId(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerInteractingStateEnteredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerInteractingStateEnteredArgs2[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs2";
/* [object, uuid("509652D6-D488-59CD-819F-F52310295B11"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsFromBinding )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2 * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_get_IsFromBinding(This,value) \
    ( (This)->lpVtbl->get_IsFromBinding(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerOwner
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerOwner[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerOwner";
/* [object, uuid("DB2E8AF3-4DEB-4E53-B29C-B06C9F96D651"), contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwnerVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CustomAnimationStateEntered )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * sender,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerCustomAnimationStateEnteredArgs * args
        );
    HRESULT ( STDMETHODCALLTYPE *IdleStateEntered )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * sender,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerIdleStateEnteredArgs * args
        );
    HRESULT ( STDMETHODCALLTYPE *InertiaStateEntered )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * sender,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInertiaStateEnteredArgs * args
        );
    HRESULT ( STDMETHODCALLTYPE *InteractingStateEntered )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * sender,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerInteractingStateEnteredArgs * args
        );
    HRESULT ( STDMETHODCALLTYPE *RequestIgnored )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * sender,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs * args
        );
    HRESULT ( STDMETHODCALLTYPE *ValuesChanged )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * sender,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs * args
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwnerVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwnerVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_CustomAnimationStateEntered(This,sender,args) \
    ( (This)->lpVtbl->CustomAnimationStateEntered(This,sender,args) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_IdleStateEntered(This,sender,args) \
    ( (This)->lpVtbl->IdleStateEntered(This,sender,args) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_InertiaStateEntered(This,sender,args) \
    ( (This)->lpVtbl->InertiaStateEntered(This,sender,args) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_InteractingStateEntered(This,sender,args) \
    ( (This)->lpVtbl->InteractingStateEntered(This,sender,args) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_RequestIgnored(This,sender,args) \
    ( (This)->lpVtbl->RequestIgnored(This,sender,args) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_ValuesChanged(This,sender,args) \
    ( (This)->lpVtbl->ValuesChanged(This,sender,args) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerRequestIgnoredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerRequestIgnoredArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerRequestIgnoredArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerRequestIgnoredArgs";
/* [object, uuid("80DD82F1-CE25-488F-91DD-CB6455CCFF2E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RequestId )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_get_RequestId(This,value) \
    ( (This)->lpVtbl->get_RequestId(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerRequestIgnoredArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerStatics[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerStatics";
/* [object, uuid("BBA5D7B7-6590-4498-8D6C-EB62B514C92A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * * result
        );
    HRESULT ( STDMETHODCALLTYPE *CreateWithOwner )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerOwner * owner,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_CreateWithOwner(This,compositor,owner,result) \
    ( (This)->lpVtbl->CreateWithOwner(This,compositor,owner,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTracker
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerStatics2[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerStatics2";
/* [object, uuid("35E53720-46B7-5CB0-B505-F3D6884A6163"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *SetBindingMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * boundTracker1,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * boundTracker2,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionBindingAxisModes axisMode
        );
    HRESULT ( STDMETHODCALLTYPE *GetBindingMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * boundTracker1,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTracker * boundTracker2,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionBindingAxisModes * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_SetBindingMode(This,boundTracker1,boundTracker2,axisMode) \
    ( (This)->lpVtbl->SetBindingMode(This,boundTracker1,boundTracker2,axisMode) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_GetBindingMode(This,boundTracker1,boundTracker2,result) \
    ( (This)->lpVtbl->GetBindingMode(This,boundTracker1,boundTracker2,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerValuesChangedArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerValuesChangedArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerValuesChangedArgs[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerValuesChangedArgs";
/* [object, uuid("CF1578EF-D3DF-4501-B9E6-F02FB22F73D0"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Position )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RequestId )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Scale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_get_Position(This,value) \
    ( (This)->lpVtbl->get_Position(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_get_RequestId(This,value) \
    ( (This)->lpVtbl->get_RequestId(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_get_Scale(This,value) \
    ( (This)->lpVtbl->get_Scale(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerValuesChangedArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaModifier
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaModifier
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaModifier[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaModifier";
/* [object, uuid("87E08AB0-3086-4853-A4B7-77882AD5D7E3"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifier_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaModifierFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaModifier
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaModifierFactory[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaModifierFactory";
/* [object, uuid("7401D6C4-6C6D-48DF-BC3E-171E227E7D7F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactoryVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaModifierFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaNaturalMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotion[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotion";
/* [object, uuid("5F17695C-162D-4C07-9400-C282B28276CA"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Condition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Condition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIExpressionAnimation * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NaturalMotion )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIVector2NaturalMotionAnimation * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_NaturalMotion )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIVector2NaturalMotionAnimation * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_get_Condition(This,value) \
    ( (This)->lpVtbl->get_Condition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_put_Condition(This,value) \
    ( (This)->lpVtbl->put_Condition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_get_NaturalMotion(This,value) \
    ( (This)->lpVtbl->get_NaturalMotion(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_put_NaturalMotion(This,value) \
    ( (This)->lpVtbl->put_NaturalMotion(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotionStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaNaturalMotion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IInteractionTrackerVector2InertiaNaturalMotionStatics[] = L"Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotionStatics";
/* [object, uuid("82001A48-09C0-434F-8189-141C66DF362F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotion * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_Create(This,compositor,result) \
    ( (This)->lpVtbl->Create(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionTrackerVector2InertiaNaturalMotionStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSource
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSource[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSource";
/* [object, uuid("CA0E8A86-D8D6-4111-B088-70347BD2B0ED"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsPositionXRailsEnabled )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsPositionXRailsEnabled )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsPositionYRailsEnabled )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsPositionYRailsEnabled )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ManipulationRedirectionMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CVisualInteractionSourceRedirectionMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ManipulationRedirectionMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CVisualInteractionSourceRedirectionMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PositionXChainingMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionChainingMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_PositionXChainingMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionChainingMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PositionXSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_PositionXSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PositionYChainingMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionChainingMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_PositionYChainingMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionChainingMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PositionYSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_PositionYSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ScaleChainingMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionChainingMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ScaleChainingMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionChainingMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ScaleSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceMode * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_ScaleSourceMode )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CInteractions_CInteractionSourceMode value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Source )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CIVisual * * value
        );
    HRESULT ( STDMETHODCALLTYPE *TryRedirectForManipulation )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CInput_CIPointerPoint * pointerPoint
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_get_IsPositionXRailsEnabled(This,value) \
    ( (This)->lpVtbl->get_IsPositionXRailsEnabled(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_put_IsPositionXRailsEnabled(This,value) \
    ( (This)->lpVtbl->put_IsPositionXRailsEnabled(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_get_IsPositionYRailsEnabled(This,value) \
    ( (This)->lpVtbl->get_IsPositionYRailsEnabled(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_put_IsPositionYRailsEnabled(This,value) \
    ( (This)->lpVtbl->put_IsPositionYRailsEnabled(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_get_ManipulationRedirectionMode(This,value) \
    ( (This)->lpVtbl->get_ManipulationRedirectionMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_put_ManipulationRedirectionMode(This,value) \
    ( (This)->lpVtbl->put_ManipulationRedirectionMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_get_PositionXChainingMode(This,value) \
    ( (This)->lpVtbl->get_PositionXChainingMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_put_PositionXChainingMode(This,value) \
    ( (This)->lpVtbl->put_PositionXChainingMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_get_PositionXSourceMode(This,value) \
    ( (This)->lpVtbl->get_PositionXSourceMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_put_PositionXSourceMode(This,value) \
    ( (This)->lpVtbl->put_PositionXSourceMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_get_PositionYChainingMode(This,value) \
    ( (This)->lpVtbl->get_PositionYChainingMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_put_PositionYChainingMode(This,value) \
    ( (This)->lpVtbl->put_PositionYChainingMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_get_PositionYSourceMode(This,value) \
    ( (This)->lpVtbl->get_PositionYSourceMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_put_PositionYSourceMode(This,value) \
    ( (This)->lpVtbl->put_PositionYSourceMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_get_ScaleChainingMode(This,value) \
    ( (This)->lpVtbl->get_ScaleChainingMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_put_ScaleChainingMode(This,value) \
    ( (This)->lpVtbl->put_ScaleChainingMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_get_ScaleSourceMode(This,value) \
    ( (This)->lpVtbl->get_ScaleSourceMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_put_ScaleSourceMode(This,value) \
    ( (This)->lpVtbl->put_ScaleSourceMode(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_get_Source(This,value) \
    ( (This)->lpVtbl->get_Source(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_TryRedirectForManipulation(This,pointerPoint) \
    ( (This)->lpVtbl->TryRedirectForManipulation(This,pointerPoint) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSource2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSource2[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSource2";
/* [object, uuid("AA914893-A73C-414D-80D0-249BAD2FBD93"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DeltaPosition )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DeltaScale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Position )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PositionVelocity )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CNumerics_CVector3 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Scale )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ScaleVelocity )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    HRESULT ( STDMETHODCALLTYPE *ConfigureCenterPointXModifiers )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
        );
    HRESULT ( STDMETHODCALLTYPE *ConfigureCenterPointYModifiers )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
        );
    HRESULT ( STDMETHODCALLTYPE *ConfigureDeltaPositionXModifiers )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
        );
    HRESULT ( STDMETHODCALLTYPE *ConfigureDeltaPositionYModifiers )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
        );
    HRESULT ( STDMETHODCALLTYPE *ConfigureDeltaScaleModifiers )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2 * This,
        /* [in] */__RPC__in_opt __FIIterable_1_Windows__CUI__CComposition__CInteractions__CCompositionConditionalValue * conditionalValues
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_get_DeltaPosition(This,value) \
    ( (This)->lpVtbl->get_DeltaPosition(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_get_DeltaScale(This,value) \
    ( (This)->lpVtbl->get_DeltaScale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_get_Position(This,value) \
    ( (This)->lpVtbl->get_Position(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_get_PositionVelocity(This,value) \
    ( (This)->lpVtbl->get_PositionVelocity(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_get_Scale(This,value) \
    ( (This)->lpVtbl->get_Scale(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_get_ScaleVelocity(This,value) \
    ( (This)->lpVtbl->get_ScaleVelocity(This,value) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_ConfigureCenterPointXModifiers(This,conditionalValues) \
    ( (This)->lpVtbl->ConfigureCenterPointXModifiers(This,conditionalValues) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_ConfigureCenterPointYModifiers(This,conditionalValues) \
    ( (This)->lpVtbl->ConfigureCenterPointYModifiers(This,conditionalValues) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_ConfigureDeltaPositionXModifiers(This,conditionalValues) \
    ( (This)->lpVtbl->ConfigureDeltaPositionXModifiers(This,conditionalValues) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_ConfigureDeltaPositionYModifiers(This,conditionalValues) \
    ( (This)->lpVtbl->ConfigureDeltaPositionYModifiers(This,conditionalValues) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_ConfigureDeltaScaleModifiers(This,conditionalValues) \
    ( (This)->lpVtbl->ConfigureDeltaScaleModifiers(This,conditionalValues) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSource3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSource3[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSource3";
/* [object, uuid("D941EF2A-0D5C-4057-92D7-C9711533204F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PointerWheelConfig )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3 * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIInteractionSourceConfiguration * * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_get_PointerWheelConfig(This,value) \
    ( (This)->lpVtbl->get_PointerWheelConfig(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSourceObjectFactory
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSourceObjectFactory[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSourceObjectFactory";
/* [object, uuid("B2CA917C-E98A-41F2-B3C9-891C9266C8F6"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactoryVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactoryVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactoryVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceObjectFactory_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSourceStatics[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics";
/* [object, uuid("369965E1-8645-4F75-BA00-6479CD10C8E6"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Create )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIVisual * source,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_Create(This,source,result) \
    ( (This)->lpVtbl->Create(This,source,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Interface Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Interactions_IVisualInteractionSourceStatics2[] = L"Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics2";
/* [object, uuid("A979C032-5764-55E0-BC1F-0778786DCFDE"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateFromIVisualElement )(
        __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIVisualElement * source,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSource * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2Vtbl;

interface __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_CreateFromIVisualElement(This,source,result) \
    ( (This)->lpVtbl->CreateFromIVisualElement(This,source,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CInteractions_CIVisualInteractionSourceStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Class Windows.UI.Composition.Interactions.CompositionConditionalValue
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.ICompositionConditionalValueStatics interface starting with version 4.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.ICompositionConditionalValue ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_CompositionConditionalValue_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_CompositionConditionalValue_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_CompositionConditionalValue[] = L"Windows.UI.Composition.Interactions.CompositionConditionalValue";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Class Windows.UI.Composition.Interactions.CompositionInteractionSourceCollection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.ICompositionInteractionSourceCollection ** Default Interface **
 *    Windows.Foundation.Collections.IIterable_1_Windows.UI.Composition.Interactions.ICompositionInteractionSource
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_CompositionInteractionSourceCollection_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_CompositionInteractionSourceCollection_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_CompositionInteractionSourceCollection[] = L"Windows.UI.Composition.Interactions.CompositionInteractionSourceCollection";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionSourceConfiguration
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionSourceConfiguration ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionSourceConfiguration_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionSourceConfiguration_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionSourceConfiguration[] = L"Windows.UI.Composition.Interactions.InteractionSourceConfiguration";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTracker
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerStatics2 interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerStatics interface starting with version 3.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTracker ** Default Interface **
 *    Windows.UI.Composition.Interactions.IInteractionTracker2
 *    Windows.UI.Composition.Interactions.IInteractionTracker3
 *    Windows.UI.Composition.Interactions.IInteractionTracker4
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTracker_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTracker_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTracker[] = L"Windows.UI.Composition.Interactions.InteractionTracker";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerCustomAnimationStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs ** Default Interface **
 *    Windows.UI.Composition.Interactions.IInteractionTrackerCustomAnimationStateEnteredArgs2
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerCustomAnimationStateEnteredArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerCustomAnimationStateEnteredArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerCustomAnimationStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerCustomAnimationStateEnteredArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerIdleStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs ** Default Interface **
 *    Windows.UI.Composition.Interactions.IInteractionTrackerIdleStateEnteredArgs2
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerIdleStateEnteredArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerIdleStateEnteredArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerIdleStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerIdleStateEnteredArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInertiaModifier
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaModifier ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaModifier_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaModifier_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaModifier[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInertiaModifier";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInertiaMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotionStatics interface starting with version 3.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaMotion ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaMotion_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaMotion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaMotion[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInertiaMotion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInertiaNaturalMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotionStatics interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaNaturalMotion ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaNaturalMotion_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaNaturalMotion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaNaturalMotion[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInertiaNaturalMotion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInertiaRestingValue
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValueStatics interface starting with version 3.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaRestingValue ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaRestingValue_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaRestingValue_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaRestingValue[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInertiaRestingValue";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInertiaStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs ** Default Interface **
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs2
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInertiaStateEnteredArgs3
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaStateEnteredArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInertiaStateEnteredArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInertiaStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInertiaStateEnteredArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerInteractingStateEnteredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs ** Default Interface **
 *    Windows.UI.Composition.Interactions.IInteractionTrackerInteractingStateEnteredArgs2
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInteractingStateEnteredArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerInteractingStateEnteredArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerInteractingStateEnteredArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerInteractingStateEnteredArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerRequestIgnoredArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerRequestIgnoredArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerRequestIgnoredArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerRequestIgnoredArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerRequestIgnoredArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerRequestIgnoredArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerValuesChangedArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerValuesChangedArgs ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerValuesChangedArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerValuesChangedArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerValuesChangedArgs[] = L"Windows.UI.Composition.Interactions.InteractionTrackerValuesChangedArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaModifier
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaModifier ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaModifier_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaModifier_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaModifier[] = L"Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaModifier";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaNaturalMotion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotionStatics interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IInteractionTrackerVector2InertiaNaturalMotion ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaNaturalMotion_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaNaturalMotion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_InteractionTrackerVector2InertiaNaturalMotion[] = L"Windows.UI.Composition.Interactions.InteractionTrackerVector2InertiaNaturalMotion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.Composition.Interactions.VisualInteractionSource
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 3.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics2 interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.UI.Composition.Interactions.IVisualInteractionSourceStatics interface starting with version 3.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Interactions.IVisualInteractionSource ** Default Interface **
 *    Windows.UI.Composition.Interactions.IVisualInteractionSource2
 *    Windows.UI.Composition.Interactions.IVisualInteractionSource3
 *    Windows.UI.Composition.Interactions.ICompositionInteractionSource
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Interactions_VisualInteractionSource_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Interactions_VisualInteractionSource_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Interactions_VisualInteractionSource[] = L"Windows.UI.Composition.Interactions.VisualInteractionSource";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x30000





#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Eui2Ecomposition2Einteractions_p_h__

#endif // __windows2Eui2Ecomposition2Einteractions_h__
