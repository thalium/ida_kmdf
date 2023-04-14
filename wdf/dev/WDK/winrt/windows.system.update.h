/* Header file automatically generated from windows.system.update.idl */
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
#ifndef __windows2Esystem2Eupdate_h__
#define __windows2Esystem2Eupdate_h__
#ifndef __windows2Esystem2Eupdate_p_h__
#define __windows2Esystem2Eupdate_p_h__


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
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                interface ISystemUpdateItem;
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem ABI::Windows::System::Update::ISystemUpdateItem

#endif // ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                interface ISystemUpdateLastErrorInfo;
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo ABI::Windows::System::Update::ISystemUpdateLastErrorInfo

#endif // ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                interface ISystemUpdateManagerStatics;
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics ABI::Windows::System::Update::ISystemUpdateManagerStatics

#endif // ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                class SystemUpdateItem;
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */


#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_USE
#define DEF___FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("f4ae5176-c068-542f-81b4-8900f72bd742"))
IIterator<ABI::Windows::System::Update::SystemUpdateItem*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::System::Update::SystemUpdateItem*, ABI::Windows::System::Update::ISystemUpdateItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.System.Update.SystemUpdateItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::System::Update::SystemUpdateItem*> __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_t;
#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::System::Update::ISystemUpdateItem*>
//#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::System::Update::ISystemUpdateItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_USE */


#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_USE
#define DEF___FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("318a3078-918c-5521-b460-0b4210360aa1"))
IIterable<ABI::Windows::System::Update::SystemUpdateItem*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::System::Update::SystemUpdateItem*, ABI::Windows::System::Update::ISystemUpdateItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.System.Update.SystemUpdateItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::System::Update::SystemUpdateItem*> __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_t;
#define __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::System::Update::ISystemUpdateItem*>
//#define __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::System::Update::ISystemUpdateItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_USE */


#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000

#ifndef DEF___FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_USE
#define DEF___FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("7c77b64c-8be2-50e0-8ca5-d8265d80902b"))
IVectorView<ABI::Windows::System::Update::SystemUpdateItem*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::System::Update::SystemUpdateItem*, ABI::Windows::System::Update::ISystemUpdateItem*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.System.Update.SystemUpdateItem>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::System::Update::SystemUpdateItem*> __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_t;
#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::System::Update::ISystemUpdateItem*>
//#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::System::Update::ISystemUpdateItem*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_USE */


#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000



#ifndef DEF___FIEventHandler_1_IInspectable_USE
#define DEF___FIEventHandler_1_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("c50898f6-c536-5f47-8583-8b2c2438a13b"))
IEventHandler<IInspectable*> : IEventHandler_impl<IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.EventHandler`1<Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IEventHandler<IInspectable*> __FIEventHandler_1_IInspectable_t;
#define __FIEventHandler_1_IInspectable ABI::Windows::Foundation::__FIEventHandler_1_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIEventHandler_1_IInspectable ABI::Windows::Foundation::IEventHandler<IInspectable*>
//#define __FIEventHandler_1_IInspectable_t ABI::Windows::Foundation::IEventHandler<IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIEventHandler_1_IInspectable_USE */




#ifndef DEF___FIIterator_1_HSTRING_USE
#define DEF___FIIterator_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("8c304ebb-6615-50a4-8829-879ecd443236"))
IIterator<HSTRING> : IIterator_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<HSTRING> __FIIterator_1_HSTRING_t;
#define __FIIterator_1_HSTRING ABI::Windows::Foundation::Collections::__FIIterator_1_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_HSTRING ABI::Windows::Foundation::Collections::IIterator<HSTRING>
//#define __FIIterator_1_HSTRING_t ABI::Windows::Foundation::Collections::IIterator<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_HSTRING_USE */




#ifndef DEF___FIIterable_1_HSTRING_USE
#define DEF___FIIterable_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("e2fcc7c1-3bfc-5a0b-b2b0-72e769d1cb7e"))
IIterable<HSTRING> : IIterable_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<HSTRING> __FIIterable_1_HSTRING_t;
#define __FIIterable_1_HSTRING ABI::Windows::Foundation::Collections::__FIIterable_1_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_HSTRING ABI::Windows::Foundation::Collections::IIterable<HSTRING>
//#define __FIIterable_1_HSTRING_t ABI::Windows::Foundation::Collections::IIterable<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_HSTRING_USE */




#ifndef DEF___FIVectorView_1_HSTRING_USE
#define DEF___FIVectorView_1_HSTRING_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("2f13c006-a03a-5f69-b090-75a43e33423e"))
IVectorView<HSTRING> : IVectorView_impl<HSTRING> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<String>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<HSTRING> __FIVectorView_1_HSTRING_t;
#define __FIVectorView_1_HSTRING ABI::Windows::Foundation::Collections::__FIVectorView_1_HSTRING_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_HSTRING ABI::Windows::Foundation::Collections::IVectorView<HSTRING>
//#define __FIVectorView_1_HSTRING_t ABI::Windows::Foundation::Collections::IVectorView<HSTRING>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_HSTRING_USE */




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
        namespace Foundation {
            
            typedef struct DateTime DateTime;
            
        } /* Foundation */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct TimeSpan TimeSpan;
            
        } /* Foundation */
    } /* Windows */} /* ABI */






namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                
                typedef enum SystemUpdateAttentionRequiredReason : int SystemUpdateAttentionRequiredReason;
                
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                
                typedef enum SystemUpdateItemState : int SystemUpdateItemState;
                
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                
                typedef enum SystemUpdateManagerState : int SystemUpdateManagerState;
                
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                
                typedef enum SystemUpdateStartInstallAction : int SystemUpdateStartInstallAction;
                
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */





namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                class SystemUpdateLastErrorInfo;
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */











/*
 *
 * Struct Windows.System.Update.SystemUpdateAttentionRequiredReason
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 */

#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                /* [v1_enum, contract] */
                enum SystemUpdateAttentionRequiredReason : int
                {
                    SystemUpdateAttentionRequiredReason_None = 0,
                    SystemUpdateAttentionRequiredReason_NetworkRequired = 1,
                    SystemUpdateAttentionRequiredReason_InsufficientDiskSpace = 2,
                    SystemUpdateAttentionRequiredReason_InsufficientBattery = 3,
                    SystemUpdateAttentionRequiredReason_UpdateBlocked = 4,
                };
                
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.System.Update.SystemUpdateItemState
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 */

#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                /* [v1_enum, contract] */
                enum SystemUpdateItemState : int
                {
                    SystemUpdateItemState_NotStarted = 0,
                    SystemUpdateItemState_Initializing = 1,
                    SystemUpdateItemState_Preparing = 2,
                    SystemUpdateItemState_Calculating = 3,
                    SystemUpdateItemState_Downloading = 4,
                    SystemUpdateItemState_Installing = 5,
                    SystemUpdateItemState_Completed = 6,
                    SystemUpdateItemState_RebootRequired = 7,
                    SystemUpdateItemState_Error = 8,
                };
                
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.System.Update.SystemUpdateManagerState
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 */

#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                /* [v1_enum, contract] */
                enum SystemUpdateManagerState : int
                {
                    SystemUpdateManagerState_Idle = 0,
                    SystemUpdateManagerState_Detecting = 1,
                    SystemUpdateManagerState_ReadyToDownload = 2,
                    SystemUpdateManagerState_Downloading = 3,
                    SystemUpdateManagerState_ReadyToInstall = 4,
                    SystemUpdateManagerState_Installing = 5,
                    SystemUpdateManagerState_RebootRequired = 6,
                    SystemUpdateManagerState_ReadyToFinalize = 7,
                    SystemUpdateManagerState_Finalizing = 8,
                    SystemUpdateManagerState_Completed = 9,
                    SystemUpdateManagerState_AttentionRequired = 10,
                    SystemUpdateManagerState_Error = 11,
                };
                
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.System.Update.SystemUpdateStartInstallAction
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 */

#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                /* [v1_enum, contract] */
                enum SystemUpdateStartInstallAction : int
                {
                    SystemUpdateStartInstallAction_UpToReboot = 0,
                    SystemUpdateStartInstallAction_AllowReboot = 1,
                };
                
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.System.Update.ISystemUpdateItem
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.System.Update.SystemUpdateItem
 *
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_System_Update_ISystemUpdateItem[] = L"Windows.System.Update.ISystemUpdateItem";
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                /* [object, uuid("779740EB-5624-519E-A8E2-09E9173B3FB7"), exclusiveto, contract] */
                MIDL_INTERFACE("779740EB-5624-519E-A8E2-09E9173B3FB7")
                ISystemUpdateItem : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_State(
                        /* [retval, out] */__RPC__out ABI::Windows::System::Update::SystemUpdateItemState * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Title(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Description(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Id(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Revision(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DownloadProgress(
                        /* [retval, out] */__RPC__out DOUBLE * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_InstallProgress(
                        /* [retval, out] */__RPC__out DOUBLE * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ISystemUpdateItem=_uuidof(ISystemUpdateItem);
                
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem;
#endif /* !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_INTERFACE_DEFINED__) */
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.System.Update.ISystemUpdateLastErrorInfo
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.System.Update.SystemUpdateLastErrorInfo
 *
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_System_Update_ISystemUpdateLastErrorInfo[] = L"Windows.System.Update.ISystemUpdateLastErrorInfo";
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                /* [object, uuid("7EE887F7-8A44-5B6E-BD07-7AECE4116EA9"), exclusiveto, contract] */
                MIDL_INTERFACE("7EE887F7-8A44-5B6E-BD07-7AECE4116EA9")
                ISystemUpdateLastErrorInfo : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_State(
                        /* [retval, out] */__RPC__out ABI::Windows::System::Update::SystemUpdateManagerState * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsInteractive(
                        /* [retval, out] */__RPC__out ::boolean * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ISystemUpdateLastErrorInfo=_uuidof(ISystemUpdateLastErrorInfo);
                
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo;
#endif /* !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.System.Update.ISystemUpdateManagerStatics
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.System.Update.SystemUpdateManager
 *
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_System_Update_ISystemUpdateManagerStatics[] = L"Windows.System.Update.ISystemUpdateManagerStatics";
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Update {
                /* [object, uuid("B2D3FCEF-2971-51BE-B41A-8BD703BB701A"), exclusiveto, contract] */
                MIDL_INTERFACE("B2D3FCEF-2971-51BE-B41A-8BD703BB701A")
                ISystemUpdateManagerStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE IsSupported(
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_State(
                        /* [retval, out] */__RPC__out ABI::Windows::System::Update::SystemUpdateManagerState * value
                        ) = 0;
                    /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_StateChanged(
                        /* [in] */__RPC__in_opt __FIEventHandler_1_IInspectable * handler,
                        /* [retval, out] */__RPC__out EventRegistrationToken * token
                        ) = 0;
                    /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_StateChanged(
                        /* [in] */EventRegistrationToken token
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DownloadProgress(
                        /* [retval, out] */__RPC__out DOUBLE * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_InstallProgress(
                        /* [retval, out] */__RPC__out DOUBLE * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UserActiveHoursStart(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UserActiveHoursEnd(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::TimeSpan * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UserActiveHoursMax(
                        /* [retval, out] */__RPC__out INT32 * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE TrySetUserActiveHours(
                        /* [in] */ABI::Windows::Foundation::TimeSpan start,
                        /* [in] */ABI::Windows::Foundation::TimeSpan end,
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LastUpdateCheckTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LastUpdateInstallTime(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::DateTime * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_LastErrorInfo(
                        /* [retval, out] */__RPC__deref_out_opt ABI::Windows::System::Update::ISystemUpdateLastErrorInfo * * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetAutomaticRebootBlockIds(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_HSTRING * * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE BlockAutomaticRebootAsync(
                        /* [in] */__RPC__in HSTRING lockId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE UnblockAutomaticRebootAsync(
                        /* [in] */__RPC__in HSTRING lockId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ExtendedError(
                        /* [retval, out] */__RPC__out HRESULT * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetUpdateItems(
                        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * * result
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_AttentionRequiredReason(
                        /* [retval, out] */__RPC__out ABI::Windows::System::Update::SystemUpdateAttentionRequiredReason * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE SetFlightRing(
                        /* [in] */__RPC__in HSTRING flightRing,
                        /* [retval, out] */__RPC__out ::boolean * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetFlightRing(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE StartInstall(
                        /* [in] */ABI::Windows::System::Update::SystemUpdateStartInstallAction action
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE RebootToCompleteInstall(void) = 0;
                    virtual HRESULT STDMETHODCALLTYPE StartCancelUpdates(void) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_ISystemUpdateManagerStatics=_uuidof(ISystemUpdateManagerStatics);
                
            } /* Update */
        } /* System */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.System.Update.SystemUpdateItem
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.System.Update.ISystemUpdateItem ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_System_Update_SystemUpdateItem_DEFINED
#define RUNTIMECLASS_Windows_System_Update_SystemUpdateItem_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_System_Update_SystemUpdateItem[] = L"Windows.System.Update.SystemUpdateItem";
#endif
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.System.Update.SystemUpdateLastErrorInfo
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.System.Update.ISystemUpdateLastErrorInfo ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_System_Update_SystemUpdateLastErrorInfo_DEFINED
#define RUNTIMECLASS_Windows_System_Update_SystemUpdateLastErrorInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_System_Update_SystemUpdateLastErrorInfo[] = L"Windows.System.Update.SystemUpdateLastErrorInfo";
#endif
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.System.Update.SystemUpdateManager
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.System.Update.ISystemUpdateManagerStatics interface starting with version 6.0 of the Windows.System.SystemManagementContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
#ifndef RUNTIMECLASS_Windows_System_Update_SystemUpdateManager_DEFINED
#define RUNTIMECLASS_Windows_System_Update_SystemUpdateManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_System_Update_SystemUpdateManager[] = L"Windows.System.Update.SystemUpdateManager";
#endif
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem;

#endif // ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo;

#endif // ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics;

#endif // ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
#if !defined(____FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem;

typedef struct __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItemVtbl;

interface __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem
{
    CONST_VTBL struct __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItemVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem_INTERFACE_DEFINED__

#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
#if !defined(____FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem;

typedef  struct __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CSystem__CUpdate__CSystemUpdateItem **first);

    END_INTERFACE
} __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItemVtbl;

interface __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem
{
    CONST_VTBL struct __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItemVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CSystem__CUpdate__CSystemUpdateItem_INTERFACE_DEFINED__

#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
#if !defined(____FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem;

typedef struct __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItemVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
            /* [in] */ __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItemVtbl;

interface __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem
{
    CONST_VTBL struct __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItemVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem_INTERFACE_DEFINED__

#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


#if !defined(____FIEventHandler_1_IInspectable_INTERFACE_DEFINED__)
#define ____FIEventHandler_1_IInspectable_INTERFACE_DEFINED__

typedef interface __FIEventHandler_1_IInspectable __FIEventHandler_1_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIEventHandler_1_IInspectable;

typedef struct __FIEventHandler_1_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIEventHandler_1_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIEventHandler_1_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIEventHandler_1_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIEventHandler_1_IInspectable * This,/* [in] */ __RPC__in_opt IInspectable *sender,/* [in] */ __RPC__in_opt IInspectable * *e);
    END_INTERFACE
} __FIEventHandler_1_IInspectableVtbl;

interface __FIEventHandler_1_IInspectable
{
    CONST_VTBL struct __FIEventHandler_1_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIEventHandler_1_IInspectable_QueryInterface(This,riid,ppvObject)	\
        ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIEventHandler_1_IInspectable_AddRef(This)	\
        ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIEventHandler_1_IInspectable_Release(This)	\
        ( (This)->lpVtbl -> Release(This) ) 

#define __FIEventHandler_1_IInspectable_Invoke(This,sender,e)	\
        ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */


#endif // ____FIEventHandler_1_IInspectable_INTERFACE_DEFINED__


#if !defined(____FIIterator_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIIterator_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIIterator_1_HSTRING __FIIterator_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_HSTRING;

typedef struct __FIIterator_1_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_HSTRING * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_HSTRING * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_HSTRING * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_HSTRING * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_HSTRING * This, /* [retval][out] */ __RPC__out HSTRING *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_HSTRING * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_HSTRING * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_HSTRING * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) HSTRING *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_HSTRINGVtbl;

interface __FIIterator_1_HSTRING
{
    CONST_VTBL struct __FIIterator_1_HSTRINGVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_HSTRING_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_HSTRING_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_HSTRING_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_HSTRING_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_HSTRING_INTERFACE_DEFINED__


#if !defined(____FIIterable_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIIterable_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIIterable_1_HSTRING __FIIterable_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_HSTRING;

typedef  struct __FIIterable_1_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_HSTRING * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_HSTRING * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_HSTRING * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_HSTRING * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_HSTRING * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_HSTRING * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_HSTRING **first);

    END_INTERFACE
} __FIIterable_1_HSTRINGVtbl;

interface __FIIterable_1_HSTRING
{
    CONST_VTBL struct __FIIterable_1_HSTRINGVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_HSTRING_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_HSTRING_INTERFACE_DEFINED__


#if !defined(____FIVectorView_1_HSTRING_INTERFACE_DEFINED__)
#define ____FIVectorView_1_HSTRING_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_HSTRING __FIVectorView_1_HSTRING;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_HSTRING;

typedef struct __FIVectorView_1_HSTRINGVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_HSTRING * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_HSTRING * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_HSTRING * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_HSTRING * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_HSTRING * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_HSTRING * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_HSTRING * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out HSTRING *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_HSTRING * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_HSTRING * This,
            /* [in] */ HSTRING item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_HSTRING * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) HSTRING *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_HSTRINGVtbl;

interface __FIVectorView_1_HSTRING
{
    CONST_VTBL struct __FIVectorView_1_HSTRINGVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_HSTRING_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_HSTRING_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_HSTRING_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_HSTRING_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_HSTRING_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_HSTRING_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_HSTRING_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_HSTRING_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_HSTRING_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_HSTRING_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_HSTRING_INTERFACE_DEFINED__


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




typedef struct __x_ABI_CWindows_CFoundation_CDateTime __x_ABI_CWindows_CFoundation_CDateTime;


typedef struct __x_ABI_CWindows_CFoundation_CTimeSpan __x_ABI_CWindows_CFoundation_CTimeSpan;







typedef enum __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateAttentionRequiredReason __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateAttentionRequiredReason;


typedef enum __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateItemState __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateItemState;


typedef enum __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateManagerState __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateManagerState;


typedef enum __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateStartInstallAction __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateStartInstallAction;















/*
 *
 * Struct Windows.System.Update.SystemUpdateAttentionRequiredReason
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 */

#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateAttentionRequiredReason
{
    SystemUpdateAttentionRequiredReason_None = 0,
    SystemUpdateAttentionRequiredReason_NetworkRequired = 1,
    SystemUpdateAttentionRequiredReason_InsufficientDiskSpace = 2,
    SystemUpdateAttentionRequiredReason_InsufficientBattery = 3,
    SystemUpdateAttentionRequiredReason_UpdateBlocked = 4,
};
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.System.Update.SystemUpdateItemState
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 */

#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateItemState
{
    SystemUpdateItemState_NotStarted = 0,
    SystemUpdateItemState_Initializing = 1,
    SystemUpdateItemState_Preparing = 2,
    SystemUpdateItemState_Calculating = 3,
    SystemUpdateItemState_Downloading = 4,
    SystemUpdateItemState_Installing = 5,
    SystemUpdateItemState_Completed = 6,
    SystemUpdateItemState_RebootRequired = 7,
    SystemUpdateItemState_Error = 8,
};
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.System.Update.SystemUpdateManagerState
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 */

#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateManagerState
{
    SystemUpdateManagerState_Idle = 0,
    SystemUpdateManagerState_Detecting = 1,
    SystemUpdateManagerState_ReadyToDownload = 2,
    SystemUpdateManagerState_Downloading = 3,
    SystemUpdateManagerState_ReadyToInstall = 4,
    SystemUpdateManagerState_Installing = 5,
    SystemUpdateManagerState_RebootRequired = 6,
    SystemUpdateManagerState_ReadyToFinalize = 7,
    SystemUpdateManagerState_Finalizing = 8,
    SystemUpdateManagerState_Completed = 9,
    SystemUpdateManagerState_AttentionRequired = 10,
    SystemUpdateManagerState_Error = 11,
};
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.System.Update.SystemUpdateStartInstallAction
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 */

#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateStartInstallAction
{
    SystemUpdateStartInstallAction_UpToReboot = 0,
    SystemUpdateStartInstallAction_AllowReboot = 1,
};
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.System.Update.ISystemUpdateItem
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.System.Update.SystemUpdateItem
 *
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_System_Update_ISystemUpdateItem[] = L"Windows.System.Update.ISystemUpdateItem";
/* [object, uuid("779740EB-5624-519E-A8E2-09E9173B3FB7"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItemVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_State )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateItemState * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Title )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Description )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Id )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Revision )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DownloadProgress )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
        /* [retval, out] */__RPC__out DOUBLE * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_InstallProgress )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
        /* [retval, out] */__RPC__out DOUBLE * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItemVtbl;

interface __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem
{
    CONST_VTBL struct __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItemVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_get_State(This,value) \
    ( (This)->lpVtbl->get_State(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_get_Title(This,value) \
    ( (This)->lpVtbl->get_Title(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_get_Description(This,value) \
    ( (This)->lpVtbl->get_Description(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_get_Id(This,value) \
    ( (This)->lpVtbl->get_Id(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_get_Revision(This,value) \
    ( (This)->lpVtbl->get_Revision(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_get_DownloadProgress(This,value) \
    ( (This)->lpVtbl->get_DownloadProgress(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_get_InstallProgress(This,value) \
    ( (This)->lpVtbl->get_InstallProgress(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem;
#endif /* !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateItem_INTERFACE_DEFINED__) */
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.System.Update.ISystemUpdateLastErrorInfo
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.System.Update.SystemUpdateLastErrorInfo
 *
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_System_Update_ISystemUpdateLastErrorInfo[] = L"Windows.System.Update.ISystemUpdateLastErrorInfo";
/* [object, uuid("7EE887F7-8A44-5B6E-BD07-7AECE4116EA9"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfoVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_State )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateManagerState * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsInteractive )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfoVtbl;

interface __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo
{
    CONST_VTBL struct __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfoVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_get_State(This,value) \
    ( (This)->lpVtbl->get_State(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_get_IsInteractive(This,value) \
    ( (This)->lpVtbl->get_IsInteractive(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo;
#endif /* !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo_INTERFACE_DEFINED__) */
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.System.Update.ISystemUpdateManagerStatics
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.System.Update.SystemUpdateManager
 *
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_System_Update_ISystemUpdateManagerStatics[] = L"Windows.System.Update.ISystemUpdateManagerStatics";
/* [object, uuid("B2D3FCEF-2971-51BE-B41A-8BD703BB701A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *IsSupported )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__out boolean * result
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_State )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateManagerState * value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_StateChanged )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [in] */__RPC__in_opt __FIEventHandler_1_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_StateChanged )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [in] */EventRegistrationToken token
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DownloadProgress )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__out DOUBLE * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_InstallProgress )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__out DOUBLE * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UserActiveHoursStart )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UserActiveHoursEnd )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CTimeSpan * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UserActiveHoursMax )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__out INT32 * value
        );
    HRESULT ( STDMETHODCALLTYPE *TrySetUserActiveHours )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan start,
        /* [in] */__x_ABI_CWindows_CFoundation_CTimeSpan end,
        /* [retval, out] */__RPC__out boolean * result
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LastUpdateCheckTime )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LastUpdateInstallTime )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CDateTime * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_LastErrorInfo )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateLastErrorInfo * * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetAutomaticRebootBlockIds )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_HSTRING * * result
        );
    HRESULT ( STDMETHODCALLTYPE *BlockAutomaticRebootAsync )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [in] */__RPC__in HSTRING lockId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *UnblockAutomaticRebootAsync )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [in] */__RPC__in HSTRING lockId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_boolean * * operation
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ExtendedError )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__out HRESULT * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetUpdateItems )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CSystem__CUpdate__CSystemUpdateItem * * result
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_AttentionRequiredReason )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateAttentionRequiredReason * value
        );
    HRESULT ( STDMETHODCALLTYPE *SetFlightRing )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [in] */__RPC__in HSTRING flightRing,
        /* [retval, out] */__RPC__out boolean * result
        );
    HRESULT ( STDMETHODCALLTYPE *GetFlightRing )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
        );
    HRESULT ( STDMETHODCALLTYPE *StartInstall )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This,
        /* [in] */__x_ABI_CWindows_CSystem_CUpdate_CSystemUpdateStartInstallAction action
        );
    HRESULT ( STDMETHODCALLTYPE *RebootToCompleteInstall )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This
        );
    HRESULT ( STDMETHODCALLTYPE *StartCancelUpdates )(
        __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics * This
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStaticsVtbl;

interface __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_IsSupported(This,result) \
    ( (This)->lpVtbl->IsSupported(This,result) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_get_State(This,value) \
    ( (This)->lpVtbl->get_State(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_add_StateChanged(This,handler,token) \
    ( (This)->lpVtbl->add_StateChanged(This,handler,token) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_remove_StateChanged(This,token) \
    ( (This)->lpVtbl->remove_StateChanged(This,token) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_get_DownloadProgress(This,value) \
    ( (This)->lpVtbl->get_DownloadProgress(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_get_InstallProgress(This,value) \
    ( (This)->lpVtbl->get_InstallProgress(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_get_UserActiveHoursStart(This,value) \
    ( (This)->lpVtbl->get_UserActiveHoursStart(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_get_UserActiveHoursEnd(This,value) \
    ( (This)->lpVtbl->get_UserActiveHoursEnd(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_get_UserActiveHoursMax(This,value) \
    ( (This)->lpVtbl->get_UserActiveHoursMax(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_TrySetUserActiveHours(This,start,end,result) \
    ( (This)->lpVtbl->TrySetUserActiveHours(This,start,end,result) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_get_LastUpdateCheckTime(This,value) \
    ( (This)->lpVtbl->get_LastUpdateCheckTime(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_get_LastUpdateInstallTime(This,value) \
    ( (This)->lpVtbl->get_LastUpdateInstallTime(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_get_LastErrorInfo(This,value) \
    ( (This)->lpVtbl->get_LastErrorInfo(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_GetAutomaticRebootBlockIds(This,result) \
    ( (This)->lpVtbl->GetAutomaticRebootBlockIds(This,result) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_BlockAutomaticRebootAsync(This,lockId,operation) \
    ( (This)->lpVtbl->BlockAutomaticRebootAsync(This,lockId,operation) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_UnblockAutomaticRebootAsync(This,lockId,operation) \
    ( (This)->lpVtbl->UnblockAutomaticRebootAsync(This,lockId,operation) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_get_ExtendedError(This,value) \
    ( (This)->lpVtbl->get_ExtendedError(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_GetUpdateItems(This,result) \
    ( (This)->lpVtbl->GetUpdateItems(This,result) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_get_AttentionRequiredReason(This,value) \
    ( (This)->lpVtbl->get_AttentionRequiredReason(This,value) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_SetFlightRing(This,flightRing,result) \
    ( (This)->lpVtbl->SetFlightRing(This,flightRing,result) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_GetFlightRing(This,result) \
    ( (This)->lpVtbl->GetFlightRing(This,result) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_StartInstall(This,action) \
    ( (This)->lpVtbl->StartInstall(This,action) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_RebootToCompleteInstall(This) \
    ( (This)->lpVtbl->RebootToCompleteInstall(This) )

#define __x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_StartCancelUpdates(This) \
    ( (This)->lpVtbl->StartCancelUpdates(This) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics;
#endif /* !defined(____x_ABI_CWindows_CSystem_CUpdate_CISystemUpdateManagerStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.System.Update.SystemUpdateItem
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.System.Update.ISystemUpdateItem ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_System_Update_SystemUpdateItem_DEFINED
#define RUNTIMECLASS_Windows_System_Update_SystemUpdateItem_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_System_Update_SystemUpdateItem[] = L"Windows.System.Update.SystemUpdateItem";
#endif
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.System.Update.SystemUpdateLastErrorInfo
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.System.Update.ISystemUpdateLastErrorInfo ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_System_Update_SystemUpdateLastErrorInfo_DEFINED
#define RUNTIMECLASS_Windows_System_Update_SystemUpdateLastErrorInfo_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_System_Update_SystemUpdateLastErrorInfo[] = L"Windows.System.Update.SystemUpdateLastErrorInfo";
#endif
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.System.Update.SystemUpdateManager
 *
 * Introduced to Windows.System.SystemManagementContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.System.Update.ISystemUpdateManagerStatics interface starting with version 6.0 of the Windows.System.SystemManagementContract API contract
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000
#ifndef RUNTIMECLASS_Windows_System_Update_SystemUpdateManager_DEFINED
#define RUNTIMECLASS_Windows_System_Update_SystemUpdateManager_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_System_Update_SystemUpdateManager[] = L"Windows.System.Update.SystemUpdateManager";
#endif
#endif // WINDOWS_SYSTEM_SYSTEMMANAGEMENTCONTRACT_VERSION >= 0x60000




#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Esystem2Eupdate_p_h__

#endif // __windows2Esystem2Eupdate_h__
