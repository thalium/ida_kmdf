/* Header file automatically generated from windows.phone.startscreen.idl */
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
#ifndef __windows2Ephone2Estartscreen_h__
#define __windows2Ephone2Estartscreen_h__
#ifndef __windows2Ephone2Estartscreen_p_h__
#define __windows2Ephone2Estartscreen_p_h__


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

#if !defined(WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION)
#define WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION)

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
#include "Windows.UI.Notifications.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace StartScreen {
                interface IDualSimTile;
            } /* StartScreen */
        } /* Phone */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile ABI::Windows::Phone::StartScreen::IDualSimTile

#endif // ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace StartScreen {
                interface IDualSimTileStatics;
            } /* StartScreen */
        } /* Phone */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics ABI::Windows::Phone::StartScreen::IDualSimTileStatics

#endif // ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace StartScreen {
                interface IToastNotificationManagerStatics3;
            } /* StartScreen */
        } /* Phone */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3 ABI::Windows::Phone::StartScreen::IToastNotificationManagerStatics3

#endif // ____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions

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
        namespace UI {
            namespace Notifications {
                class BadgeUpdater;
            } /* Notifications */
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CNotifications_CIBadgeUpdater_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CNotifications_CIBadgeUpdater_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Notifications {
                interface IBadgeUpdater;
            } /* Notifications */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CNotifications_CIBadgeUpdater ABI::Windows::UI::Notifications::IBadgeUpdater

#endif // ____x_ABI_CWindows_CUI_CNotifications_CIBadgeUpdater_FWD_DEFINED__


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Notifications {
                class TileUpdater;
            } /* Notifications */
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CNotifications_CITileUpdater_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CNotifications_CITileUpdater_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Notifications {
                interface ITileUpdater;
            } /* Notifications */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CNotifications_CITileUpdater ABI::Windows::UI::Notifications::ITileUpdater

#endif // ____x_ABI_CWindows_CUI_CNotifications_CITileUpdater_FWD_DEFINED__


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Notifications {
                class ToastNotifier;
            } /* Notifications */
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CNotifications_CIToastNotifier_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CNotifications_CIToastNotifier_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace Notifications {
                interface IToastNotifier;
            } /* Notifications */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CNotifications_CIToastNotifier ABI::Windows::UI::Notifications::IToastNotifier

#endif // ____x_ABI_CWindows_CUI_CNotifications_CIToastNotifier_FWD_DEFINED__









namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace StartScreen {
                class DualSimTile;
            } /* StartScreen */
        } /* Phone */
    } /* Windows */} /* ABI */







/*
 *
 * Interface Windows.Phone.StartScreen.IDualSimTile
 *
 * Introduced to Windows.Phone.StartScreen.DualSimTileContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Phone.StartScreen.DualSimTile
 *
 *
 */
#if WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_StartScreen_IDualSimTile[] = L"Windows.Phone.StartScreen.IDualSimTile";
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace StartScreen {
                /* [object, uuid("143AB213-D05F-4041-A18C-3E3FCB75B41E"), exclusiveto, contract] */
                MIDL_INTERFACE("143AB213-D05F-4041-A18C-3E3FCB75B41E")
                IDualSimTile : public IInspectable
                {
                public:
                    /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_DisplayName(
                        /* [in] */__RPC__in HSTRING value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsPinnedToStart(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE UpdateAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE DeleteAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDualSimTile=_uuidof(IDualSimTile);
                
            } /* StartScreen */
        } /* Phone */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile;
#endif /* !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.StartScreen.IDualSimTileStatics
 *
 * Introduced to Windows.Phone.StartScreen.DualSimTileContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Phone.StartScreen.DualSimTile
 *
 *
 */
#if WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_StartScreen_IDualSimTileStatics[] = L"Windows.Phone.StartScreen.IDualSimTileStatics";
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace StartScreen {
                /* [object, uuid("50567C9E-C58F-4DC9-B6E8-FA6777EEEB37"), exclusiveto, contract] */
                MIDL_INTERFACE("50567C9E-C58F-4DC9-B6E8-FA6777EEEB37")
                IDualSimTileStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetTileForSim2(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Phone::StartScreen::IDualSimTile * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE UpdateDisplayNameForSim1Async(
                        /* [in] */__RPC__in HSTRING name,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateTileUpdaterForSim1(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Notifications::ITileUpdater * * updater
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateTileUpdaterForSim2(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Notifications::ITileUpdater * * updater
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateBadgeUpdaterForSim1(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Notifications::IBadgeUpdater * * updater
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateBadgeUpdaterForSim2(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Notifications::IBadgeUpdater * * updater
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateToastNotifierForSim1(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Notifications::IToastNotifier * * notifier
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE CreateToastNotifierForSim2(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Notifications::IToastNotifier * * notifier
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDualSimTileStatics=_uuidof(IDualSimTileStatics);
                
            } /* StartScreen */
        } /* Phone */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics;
#endif /* !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.StartScreen.IToastNotificationManagerStatics3
 *
 * Introduced to Windows.Phone.StartScreen.DualSimTileContract in version 1.0
 *
 *
 */
#if WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_StartScreen_IToastNotificationManagerStatics3[] = L"Windows.Phone.StartScreen.IToastNotificationManagerStatics3";
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace StartScreen {
                /* [object, uuid("2717F54B-50DF-4455-8E6E-41E0FC8E13CE"), contract] */
                MIDL_INTERFACE("2717F54B-50DF-4455-8E6E-41E0FC8E13CE")
                IToastNotificationManagerStatics3 : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE CreateToastNotifierForSecondaryTile(
                        /* [in] */__RPC__in HSTRING tileId,
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::Notifications::IToastNotifier * * notifier
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IToastNotificationManagerStatics3=_uuidof(IToastNotificationManagerStatics3);
                
            } /* StartScreen */
        } /* Phone */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3;
#endif /* !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Phone.StartScreen.DualSimTile
 *
 * Introduced to Windows.Phone.StartScreen.DualSimTileContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Phone.StartScreen.DualSimTileContract API contract
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Phone.StartScreen.IDualSimTileStatics interface starting with version 1.0 of the Windows.Phone.StartScreen.DualSimTileContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Phone.StartScreen.IDualSimTile ** Default Interface **
 *
 * Class Threading Model:  Multi Threaded Apartment
 *
 */
#if WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Phone_StartScreen_DualSimTile_DEFINED
#define RUNTIMECLASS_Windows_Phone_StartScreen_DualSimTile_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Phone_StartScreen_DualSimTile[] = L"Windows.Phone.StartScreen.DualSimTile";
#endif
#endif // WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile;

#endif // ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics;

#endif // ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3 __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3;

#endif // ____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions
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



#ifndef ____x_ABI_CWindows_CUI_CNotifications_CIBadgeUpdater_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CNotifications_CIBadgeUpdater_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CNotifications_CIBadgeUpdater __x_ABI_CWindows_CUI_CNotifications_CIBadgeUpdater;

#endif // ____x_ABI_CWindows_CUI_CNotifications_CIBadgeUpdater_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CNotifications_CITileUpdater_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CNotifications_CITileUpdater_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CNotifications_CITileUpdater __x_ABI_CWindows_CUI_CNotifications_CITileUpdater;

#endif // ____x_ABI_CWindows_CUI_CNotifications_CITileUpdater_FWD_DEFINED__


#ifndef ____x_ABI_CWindows_CUI_CNotifications_CIToastNotifier_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CNotifications_CIToastNotifier_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CNotifications_CIToastNotifier __x_ABI_CWindows_CUI_CNotifications_CIToastNotifier;

#endif // ____x_ABI_CWindows_CUI_CNotifications_CIToastNotifier_FWD_DEFINED__















/*
 *
 * Interface Windows.Phone.StartScreen.IDualSimTile
 *
 * Introduced to Windows.Phone.StartScreen.DualSimTileContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Phone.StartScreen.DualSimTile
 *
 *
 */
#if WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_StartScreen_IDualSimTile[] = L"Windows.Phone.StartScreen.IDualSimTile";
/* [object, uuid("143AB213-D05F-4041-A18C-3E3FCB75B41E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propput] */HRESULT ( STDMETHODCALLTYPE *put_DisplayName )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayName )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsPinnedToStart )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    HRESULT ( STDMETHODCALLTYPE *CreateAsync )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *UpdateAsync )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *DeleteAsync )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileVtbl;

interface __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile
{
    CONST_VTBL struct __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_put_DisplayName(This,value) \
    ( (This)->lpVtbl->put_DisplayName(This,value) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_get_DisplayName(This,value) \
    ( (This)->lpVtbl->get_DisplayName(This,value) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_get_IsPinnedToStart(This,value) \
    ( (This)->lpVtbl->get_IsPinnedToStart(This,value) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_CreateAsync(This,operation) \
    ( (This)->lpVtbl->CreateAsync(This,operation) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_UpdateAsync(This,operation) \
    ( (This)->lpVtbl->UpdateAsync(This,operation) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_DeleteAsync(This,operation) \
    ( (This)->lpVtbl->DeleteAsync(This,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile;
#endif /* !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.StartScreen.IDualSimTileStatics
 *
 * Introduced to Windows.Phone.StartScreen.DualSimTileContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Phone.StartScreen.DualSimTile
 *
 *
 */
#if WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_StartScreen_IDualSimTileStatics[] = L"Windows.Phone.StartScreen.IDualSimTileStatics";
/* [object, uuid("50567C9E-C58F-4DC9-B6E8-FA6777EEEB37"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetTileForSim2 )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTile * * result
        );
    HRESULT ( STDMETHODCALLTYPE *UpdateDisplayNameForSim1Async )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
        /* [in] */__RPC__in HSTRING name,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *CreateTileUpdaterForSim1 )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CNotifications_CITileUpdater * * updater
        );
    HRESULT ( STDMETHODCALLTYPE *CreateTileUpdaterForSim2 )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CNotifications_CITileUpdater * * updater
        );
    HRESULT ( STDMETHODCALLTYPE *CreateBadgeUpdaterForSim1 )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CNotifications_CIBadgeUpdater * * updater
        );
    HRESULT ( STDMETHODCALLTYPE *CreateBadgeUpdaterForSim2 )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CNotifications_CIBadgeUpdater * * updater
        );
    HRESULT ( STDMETHODCALLTYPE *CreateToastNotifierForSim1 )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CNotifications_CIToastNotifier * * notifier
        );
    HRESULT ( STDMETHODCALLTYPE *CreateToastNotifierForSim2 )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CNotifications_CIToastNotifier * * notifier
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStaticsVtbl;

interface __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_GetTileForSim2(This,result) \
    ( (This)->lpVtbl->GetTileForSim2(This,result) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_UpdateDisplayNameForSim1Async(This,name,operation) \
    ( (This)->lpVtbl->UpdateDisplayNameForSim1Async(This,name,operation) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_CreateTileUpdaterForSim1(This,updater) \
    ( (This)->lpVtbl->CreateTileUpdaterForSim1(This,updater) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_CreateTileUpdaterForSim2(This,updater) \
    ( (This)->lpVtbl->CreateTileUpdaterForSim2(This,updater) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_CreateBadgeUpdaterForSim1(This,updater) \
    ( (This)->lpVtbl->CreateBadgeUpdaterForSim1(This,updater) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_CreateBadgeUpdaterForSim2(This,updater) \
    ( (This)->lpVtbl->CreateBadgeUpdaterForSim2(This,updater) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_CreateToastNotifierForSim1(This,notifier) \
    ( (This)->lpVtbl->CreateToastNotifierForSim1(This,notifier) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_CreateToastNotifierForSim2(This,notifier) \
    ( (This)->lpVtbl->CreateToastNotifierForSim2(This,notifier) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics;
#endif /* !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIDualSimTileStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.StartScreen.IToastNotificationManagerStatics3
 *
 * Introduced to Windows.Phone.StartScreen.DualSimTileContract in version 1.0
 *
 *
 */
#if WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_StartScreen_IToastNotificationManagerStatics3[] = L"Windows.Phone.StartScreen.IToastNotificationManagerStatics3";
/* [object, uuid("2717F54B-50DF-4455-8E6E-41E0FC8E13CE"), contract] */
typedef struct __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *CreateToastNotifierForSecondaryTile )(
        __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3 * This,
        /* [in] */__RPC__in HSTRING tileId,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CNotifications_CIToastNotifier * * notifier
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3Vtbl;

interface __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3
{
    CONST_VTBL struct __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_CreateToastNotifierForSecondaryTile(This,tileId,notifier) \
    ( (This)->lpVtbl->CreateToastNotifierForSecondaryTile(This,tileId,notifier) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3;
#endif /* !defined(____x_ABI_CWindows_CPhone_CStartScreen_CIToastNotificationManagerStatics3_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Phone.StartScreen.DualSimTile
 *
 * Introduced to Windows.Phone.StartScreen.DualSimTileContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Phone.StartScreen.DualSimTileContract API contract
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Phone.StartScreen.IDualSimTileStatics interface starting with version 1.0 of the Windows.Phone.StartScreen.DualSimTileContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Phone.StartScreen.IDualSimTile ** Default Interface **
 *
 * Class Threading Model:  Multi Threaded Apartment
 *
 */
#if WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Phone_StartScreen_DualSimTile_DEFINED
#define RUNTIMECLASS_Windows_Phone_StartScreen_DualSimTile_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Phone_StartScreen_DualSimTile[] = L"Windows.Phone.StartScreen.DualSimTile";
#endif
#endif // WINDOWS_PHONE_STARTSCREEN_DUALSIMTILECONTRACT_VERSION >= 0x10000




#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Ephone2Estartscreen_p_h__

#endif // __windows2Ephone2Estartscreen_h__
