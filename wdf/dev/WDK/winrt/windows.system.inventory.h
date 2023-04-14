/* Header file automatically generated from windows.system.inventory.idl */
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
#ifndef __windows2Esystem2Einventory_h__
#define __windows2Esystem2Einventory_h__
#ifndef __windows2Esystem2Einventory_p_h__
#define __windows2Esystem2Einventory_p_h__


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
#if !defined(WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION)
#define WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION 0x50000
#endif // defined(WINDOWS_APPLICATIONMODEL_CALLS_CALLSPHONECONTRACT_VERSION)

#if !defined(WINDOWS_FOUNDATION_FOUNDATIONCONTRACT_VERSION)
#define WINDOWS_FOUNDATION_FOUNDATIONCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_FOUNDATION_FOUNDATIONCONTRACT_VERSION)

#if !defined(WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION)
#define WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION 0x80000
#endif // defined(WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION)

#if !defined(WINDOWS_NETWORKING_SOCKETS_CONTROLCHANNELTRIGGERCONTRACT_VERSION)
#define WINDOWS_NETWORKING_SOCKETS_CONTROLCHANNELTRIGGERCONTRACT_VERSION 0x30000
#endif // defined(WINDOWS_NETWORKING_SOCKETS_CONTROLCHANNELTRIGGERCONTRACT_VERSION)

#if !defined(WINDOWS_PHONE_PHONECONTRACT_VERSION)
#define WINDOWS_PHONE_PHONECONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_PHONE_PHONECONTRACT_VERSION)

#if !defined(WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION)
#define WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION 0x10000
#endif // defined(WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION)

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
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Inventory {
                interface IInstalledDesktopApp;
            } /* Inventory */
        } /* System */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp ABI::Windows::System::Inventory::IInstalledDesktopApp

#endif // ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Inventory {
                interface IInstalledDesktopAppStatics;
            } /* Inventory */
        } /* System */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics ABI::Windows::System::Inventory::IInstalledDesktopAppStatics

#endif // ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Inventory {
                class InstalledDesktopApp;
            } /* Inventory */
        } /* System */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE
#define DEF___FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("af3da06d-0a82-5213-9cb5-f8d2da12fbe9"))
IIterator<ABI::Windows::System::Inventory::InstalledDesktopApp*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::System::Inventory::InstalledDesktopApp*, ABI::Windows::System::Inventory::IInstalledDesktopApp*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.System.Inventory.InstalledDesktopApp>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::System::Inventory::InstalledDesktopApp*> __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t;
#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::System::Inventory::IInstalledDesktopApp*>
//#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::System::Inventory::IInstalledDesktopApp*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE
#define DEF___FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("b64037f2-dc1a-57de-8b03-18a16f9ddbdf"))
IIterable<ABI::Windows::System::Inventory::InstalledDesktopApp*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::System::Inventory::InstalledDesktopApp*, ABI::Windows::System::Inventory::IInstalledDesktopApp*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.System.Inventory.InstalledDesktopApp>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::System::Inventory::InstalledDesktopApp*> __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t;
#define __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::System::Inventory::IInstalledDesktopApp*>
//#define __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::System::Inventory::IInstalledDesktopApp*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE
#define DEF___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("ba3a2146-42dd-5fa8-a7f0-36b6973803b5"))
IVectorView<ABI::Windows::System::Inventory::InstalledDesktopApp*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::System::Inventory::InstalledDesktopApp*, ABI::Windows::System::Inventory::IInstalledDesktopApp*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.System.Inventory.InstalledDesktopApp>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::System::Inventory::InstalledDesktopApp*> __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t;
#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::System::Inventory::IInstalledDesktopApp*>
//#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::System::Inventory::IInstalledDesktopApp*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE
#define DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("eb945c7c-7edd-565a-8bcc-82baf4ea17b6"))
IAsyncOperationCompletedHandler<__FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp*> : IAsyncOperationCompletedHandler_impl<__FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Foundation.Collections.IVectorView`1<Windows.System.Inventory.InstalledDesktopApp>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<__FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp*> __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t;
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::System::Inventory::IInstalledDesktopApp*>*>
//#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::System::Inventory::IInstalledDesktopApp*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE
#define DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("9ffdaf80-6d25-5e34-9886-2b5d541d8324"))
IAsyncOperation<__FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp*> : IAsyncOperation_impl<__FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Foundation.Collections.IVectorView`1<Windows.System.Inventory.InstalledDesktopApp>>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<__FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp*> __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t;
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp ABI::Windows::Foundation::__FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::System::Inventory::IInstalledDesktopApp*>*>
//#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::System::Inventory::IInstalledDesktopApp*>*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#ifndef ____x_ABI_CWindows_CFoundation_CIStringable_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIStringable_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Foundation {
            interface IStringable;
        } /* Foundation */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CFoundation_CIStringable ABI::Windows::Foundation::IStringable

#endif // ____x_ABI_CWindows_CFoundation_CIStringable_FWD_DEFINED__
















/*
 *
 * Interface Windows.System.Inventory.IInstalledDesktopApp
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.System.Inventory.InstalledDesktopApp
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_System_Inventory_IInstalledDesktopApp[] = L"Windows.System.Inventory.IInstalledDesktopApp";
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Inventory {
                /* [object, uuid("75EAB8ED-C0BC-5364-4C28-166E0545167A"), exclusiveto, contract] */
                MIDL_INTERFACE("75EAB8ED-C0BC-5364-4C28-166E0545167A")
                IInstalledDesktopApp : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Id(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Publisher(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayVersion(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IInstalledDesktopApp=_uuidof(IInstalledDesktopApp);
                
            } /* Inventory */
        } /* System */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp;
#endif /* !defined(____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.System.Inventory.IInstalledDesktopAppStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.System.Inventory.InstalledDesktopApp
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_System_Inventory_IInstalledDesktopAppStatics[] = L"Windows.System.Inventory.IInstalledDesktopAppStatics";
namespace ABI {
    namespace Windows {
        namespace System {
            namespace Inventory {
                /* [object, uuid("264CF74E-21CD-5F9B-6056-7866AD72489A"), exclusiveto, contract] */
                MIDL_INTERFACE("264CF74E-21CD-5F9B-6056-7866AD72489A")
                IInstalledDesktopAppStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetInventoryAsync(
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IInstalledDesktopAppStatics=_uuidof(IInstalledDesktopAppStatics);
                
            } /* Inventory */
        } /* System */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics;
#endif /* !defined(____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.System.Inventory.InstalledDesktopApp
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.System.Inventory.IInstalledDesktopAppStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.System.Inventory.IInstalledDesktopApp ** Default Interface **
 *    Windows.Foundation.IStringable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_System_Inventory_InstalledDesktopApp_DEFINED
#define RUNTIMECLASS_Windows_System_Inventory_InstalledDesktopApp_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_System_Inventory_InstalledDesktopApp[] = L"Windows.System.Inventory.InstalledDesktopApp";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp;

#endif // ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics;

#endif // ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp;

typedef struct __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl;

interface __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp
{
    CONST_VTBL struct __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp;

typedef  struct __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CSystem__CInventory__CInstalledDesktopApp **first);

    END_INTERFACE
} __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl;

interface __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp
{
    CONST_VTBL struct __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp;

typedef struct __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
            /* [in] */ __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl;

interface __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp
{
    CONST_VTBL struct __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp;

typedef struct __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl;

interface __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp;

typedef struct __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * This, /* [retval][out] */ __RPC__out __FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * *results);
    END_INTERFACE
} __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl;

interface __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp
{
    CONST_VTBL struct __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopAppVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#ifndef ____x_ABI_CWindows_CFoundation_CIStringable_FWD_DEFINED__
#define ____x_ABI_CWindows_CFoundation_CIStringable_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CFoundation_CIStringable __x_ABI_CWindows_CFoundation_CIStringable;

#endif // ____x_ABI_CWindows_CFoundation_CIStringable_FWD_DEFINED__
















/*
 *
 * Interface Windows.System.Inventory.IInstalledDesktopApp
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.System.Inventory.InstalledDesktopApp
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_System_Inventory_IInstalledDesktopApp[] = L"Windows.System.Inventory.IInstalledDesktopApp";
/* [object, uuid("75EAB8ED-C0BC-5364-4C28-166E0545167A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Id )(
        __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayName )(
        __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Publisher )(
        __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayVersion )(
        __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppVtbl;

interface __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp
{
    CONST_VTBL struct __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_get_Id(This,value) \
    ( (This)->lpVtbl->get_Id(This,value) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_get_DisplayName(This,value) \
    ( (This)->lpVtbl->get_DisplayName(This,value) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_get_Publisher(This,value) \
    ( (This)->lpVtbl->get_Publisher(This,value) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_get_DisplayVersion(This,value) \
    ( (This)->lpVtbl->get_DisplayVersion(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp;
#endif /* !defined(____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopApp_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.System.Inventory.IInstalledDesktopAppStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.System.Inventory.InstalledDesktopApp
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_System_Inventory_IInstalledDesktopAppStatics[] = L"Windows.System.Inventory.IInstalledDesktopAppStatics";
/* [object, uuid("264CF74E-21CD-5F9B-6056-7866AD72489A"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetInventoryAsync )(
        __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1___FIVectorView_1_Windows__CSystem__CInventory__CInstalledDesktopApp * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStaticsVtbl;

interface __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_GetInventoryAsync(This,operation) \
    ( (This)->lpVtbl->GetInventoryAsync(This,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics;
#endif /* !defined(____x_ABI_CWindows_CSystem_CInventory_CIInstalledDesktopAppStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.System.Inventory.InstalledDesktopApp
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.System.Inventory.IInstalledDesktopAppStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.System.Inventory.IInstalledDesktopApp ** Default Interface **
 *    Windows.Foundation.IStringable
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_System_Inventory_InstalledDesktopApp_DEFINED
#define RUNTIMECLASS_Windows_System_Inventory_InstalledDesktopApp_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_System_Inventory_InstalledDesktopApp[] = L"Windows.System.Inventory.InstalledDesktopApp";
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
#endif // __windows2Esystem2Einventory_p_h__

#endif // __windows2Esystem2Einventory_h__
