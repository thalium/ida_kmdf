/* Header file automatically generated from windows.ui.composition.diagnostics.idl */
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
#ifndef __windows2Eui2Ecomposition2Ediagnostics_h__
#define __windows2Eui2Ecomposition2Ediagnostics_h__
#ifndef __windows2Eui2Ecomposition2Ediagnostics_p_h__
#define __windows2Eui2Ecomposition2Ediagnostics_p_h__


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
#ifndef ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Diagnostics {
                    interface ICompositionDebugHeatMaps;
                } /* Diagnostics */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps ABI::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps

#endif // ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Diagnostics {
                    interface ICompositionDebugSettings;
                } /* Diagnostics */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings ABI::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings

#endif // ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Diagnostics {
                    interface ICompositionDebugSettingsStatics;
                } /* Diagnostics */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics ABI::Windows::UI::Composition::Diagnostics::ICompositionDebugSettingsStatics

#endif // ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_FWD_DEFINED__





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
            namespace Composition {
                namespace Diagnostics {
                    
                    typedef enum CompositionDebugOverdrawContentKinds : unsigned int CompositionDebugOverdrawContentKinds;
                    
                } /* Diagnostics */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Diagnostics {
                    class CompositionDebugHeatMaps;
                } /* Diagnostics */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Diagnostics {
                    class CompositionDebugSettings;
                } /* Diagnostics */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */







/*
 *
 * Struct Windows.UI.Composition.Diagnostics.CompositionDebugOverdrawContentKinds
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Diagnostics {
                    /* [v1_enum, flags, contract] */
                    enum CompositionDebugOverdrawContentKinds : unsigned int
                    {
                        CompositionDebugOverdrawContentKinds_None = 0,
                        CompositionDebugOverdrawContentKinds_OffscreenRendered = 0x1,
                        CompositionDebugOverdrawContentKinds_Colors = 0x2,
                        CompositionDebugOverdrawContentKinds_Effects = 0x4,
                        CompositionDebugOverdrawContentKinds_Shadows = 0x8,
                        CompositionDebugOverdrawContentKinds_Lights = 0x10,
                        CompositionDebugOverdrawContentKinds_Surfaces = 0x20,
                        CompositionDebugOverdrawContentKinds_SwapChains = 0x40,
                        CompositionDebugOverdrawContentKinds_All = 0xffffffff,
                    };
                    
                    DEFINE_ENUM_FLAG_OPERATORS(CompositionDebugOverdrawContentKinds)
                    
                } /* Diagnostics */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.UI.Composition.Diagnostics.ICompositionDebugHeatMaps
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Diagnostics.CompositionDebugHeatMaps
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Diagnostics_ICompositionDebugHeatMaps[] = L"Windows.UI.Composition.Diagnostics.ICompositionDebugHeatMaps";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Diagnostics {
                    /* [object, uuid("E49C90AC-2FF3-5805-718C-B725EE07650F"), exclusiveto, contract] */
                    MIDL_INTERFACE("E49C90AC-2FF3-5805-718C-B725EE07650F")
                    ICompositionDebugHeatMaps : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE Hide(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IVisual * subtree
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ShowMemoryUsage(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IVisual * subtree
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ShowOverdraw(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IVisual * subtree,
                            /* [in] */ABI::Windows::UI::Composition::Diagnostics::CompositionDebugOverdrawContentKinds contentKinds
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE ShowRedraw(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::IVisual * subtree
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICompositionDebugHeatMaps=_uuidof(ICompositionDebugHeatMaps);
                    
                } /* Diagnostics */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.UI.Composition.Diagnostics.ICompositionDebugSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Diagnostics.CompositionDebugSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Diagnostics_ICompositionDebugSettings[] = L"Windows.UI.Composition.Diagnostics.ICompositionDebugSettings";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Diagnostics {
                    /* [object, uuid("2831987E-1D82-4D38-B7B7-EFD11C7BC3D1"), exclusiveto, contract] */
                    MIDL_INTERFACE("2831987E-1D82-4D38-B7B7-EFD11C7BC3D1")
                    ICompositionDebugSettings : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_HeatMaps(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Diagnostics::ICompositionDebugHeatMaps * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICompositionDebugSettings=_uuidof(ICompositionDebugSettings);
                    
                } /* Diagnostics */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.UI.Composition.Diagnostics.ICompositionDebugSettingsStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Diagnostics.CompositionDebugSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Diagnostics_ICompositionDebugSettingsStatics[] = L"Windows.UI.Composition.Diagnostics.ICompositionDebugSettingsStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Composition {
                namespace Diagnostics {
                    /* [object, uuid("64EC1F1E-6AF8-4AF8-B814-C870FD5A9505"), exclusiveto, contract] */
                    MIDL_INTERFACE("64EC1F1E-6AF8-4AF8-B814-C870FD5A9505")
                    ICompositionDebugSettingsStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE TryGetSettings(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::Composition::ICompositor * compositor,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Composition::Diagnostics::ICompositionDebugSettings * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICompositionDebugSettingsStatics=_uuidof(ICompositionDebugSettingsStatics);
                    
                } /* Diagnostics */
            } /* Composition */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.UI.Composition.Diagnostics.CompositionDebugHeatMaps
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Diagnostics.ICompositionDebugHeatMaps ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Diagnostics_CompositionDebugHeatMaps_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Diagnostics_CompositionDebugHeatMaps_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Diagnostics_CompositionDebugHeatMaps[] = L"Windows.UI.Composition.Diagnostics.CompositionDebugHeatMaps";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.UI.Composition.Diagnostics.CompositionDebugSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Diagnostics.ICompositionDebugSettingsStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Diagnostics.ICompositionDebugSettings ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Diagnostics_CompositionDebugSettings_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Diagnostics_CompositionDebugSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Diagnostics_CompositionDebugSettings[] = L"Windows.UI.Composition.Diagnostics.CompositionDebugSettings";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000





#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps;

#endif // ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings;

#endif // ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics;

#endif // ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_FWD_DEFINED__




#ifndef ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CICompositor __x_ABI_CWindows_CUI_CComposition_CICompositor;

#endif // ____x_ABI_CWindows_CUI_CComposition_CICompositor_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CComposition_CIVisual __x_ABI_CWindows_CUI_CComposition_CIVisual;

#endif // ____x_ABI_CWindows_CUI_CComposition_CIVisual_FWD_DEFINED__






typedef enum __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CCompositionDebugOverdrawContentKinds __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CCompositionDebugOverdrawContentKinds;











/*
 *
 * Struct Windows.UI.Composition.Diagnostics.CompositionDebugOverdrawContentKinds
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, flags, contract] */
enum __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CCompositionDebugOverdrawContentKinds
{
    CompositionDebugOverdrawContentKinds_None = 0,
    CompositionDebugOverdrawContentKinds_OffscreenRendered = 0x1,
    CompositionDebugOverdrawContentKinds_Colors = 0x2,
    CompositionDebugOverdrawContentKinds_Effects = 0x4,
    CompositionDebugOverdrawContentKinds_Shadows = 0x8,
    CompositionDebugOverdrawContentKinds_Lights = 0x10,
    CompositionDebugOverdrawContentKinds_Surfaces = 0x20,
    CompositionDebugOverdrawContentKinds_SwapChains = 0x40,
    CompositionDebugOverdrawContentKinds_All = 0xffffffff,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.UI.Composition.Diagnostics.ICompositionDebugHeatMaps
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Diagnostics.CompositionDebugHeatMaps
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Diagnostics_ICompositionDebugHeatMaps[] = L"Windows.UI.Composition.Diagnostics.ICompositionDebugHeatMaps";
/* [object, uuid("E49C90AC-2FF3-5805-718C-B725EE07650F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMapsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *Hide )(
        __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIVisual * subtree
        );
    HRESULT ( STDMETHODCALLTYPE *ShowMemoryUsage )(
        __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIVisual * subtree
        );
    HRESULT ( STDMETHODCALLTYPE *ShowOverdraw )(
        __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIVisual * subtree,
        /* [in] */__x_ABI_CWindows_CUI_CComposition_CDiagnostics_CCompositionDebugOverdrawContentKinds contentKinds
        );
    HRESULT ( STDMETHODCALLTYPE *ShowRedraw )(
        __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CIVisual * subtree
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMapsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMapsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_Hide(This,subtree) \
    ( (This)->lpVtbl->Hide(This,subtree) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_ShowMemoryUsage(This,subtree) \
    ( (This)->lpVtbl->ShowMemoryUsage(This,subtree) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_ShowOverdraw(This,subtree,contentKinds) \
    ( (This)->lpVtbl->ShowOverdraw(This,subtree,contentKinds) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_ShowRedraw(This,subtree) \
    ( (This)->lpVtbl->ShowRedraw(This,subtree) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.UI.Composition.Diagnostics.ICompositionDebugSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Diagnostics.CompositionDebugSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Diagnostics_ICompositionDebugSettings[] = L"Windows.UI.Composition.Diagnostics.ICompositionDebugSettings";
/* [object, uuid("2831987E-1D82-4D38-B7B7-EFD11C7BC3D1"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_HeatMaps )(
        __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugHeatMaps * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_get_HeatMaps(This,result) \
    ( (This)->lpVtbl->get_HeatMaps(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.UI.Composition.Diagnostics.ICompositionDebugSettingsStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.Composition.Diagnostics.CompositionDebugSettings
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_Composition_Diagnostics_ICompositionDebugSettingsStatics[] = L"Windows.UI.Composition.Diagnostics.ICompositionDebugSettingsStatics";
/* [object, uuid("64EC1F1E-6AF8-4AF8-B814-C870FD5A9505"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *TryGetSettings )(
        __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CComposition_CICompositor * compositor,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettings * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStaticsVtbl;

interface __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_TryGetSettings(This,compositor,result) \
    ( (This)->lpVtbl->TryGetSettings(This,compositor,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CComposition_CDiagnostics_CICompositionDebugSettingsStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.UI.Composition.Diagnostics.CompositionDebugHeatMaps
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Diagnostics.ICompositionDebugHeatMaps ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Diagnostics_CompositionDebugHeatMaps_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Diagnostics_CompositionDebugHeatMaps_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Diagnostics_CompositionDebugHeatMaps[] = L"Windows.UI.Composition.Diagnostics.CompositionDebugHeatMaps";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.UI.Composition.Diagnostics.CompositionDebugSettings
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.Composition.Diagnostics.ICompositionDebugSettingsStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.Composition.Diagnostics.ICompositionDebugSettings ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_UI_Composition_Diagnostics_CompositionDebugSettings_DEFINED
#define RUNTIMECLASS_Windows_UI_Composition_Diagnostics_CompositionDebugSettings_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_Composition_Diagnostics_CompositionDebugSettings[] = L"Windows.UI.Composition.Diagnostics.CompositionDebugSettings";
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
#endif // __windows2Eui2Ecomposition2Ediagnostics_p_h__

#endif // __windows2Eui2Ecomposition2Ediagnostics_h__
