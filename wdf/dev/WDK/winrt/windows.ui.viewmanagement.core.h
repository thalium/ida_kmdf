/* Header file automatically generated from windows.ui.viewmanagement.core.idl */
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
#ifndef __windows2Eui2Eviewmanagement2Ecore_h__
#define __windows2Eui2Eviewmanagement2Ecore_h__
#ifndef __windows2Eui2Eviewmanagement2Ecore_p_h__
#define __windows2Eui2Eviewmanagement2Ecore_p_h__


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
#include "Windows.UI.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    interface ICoreInputView;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView ABI::Windows::UI::ViewManagement::Core::ICoreInputView

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    interface ICoreInputView2;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 ABI::Windows::UI::ViewManagement::Core::ICoreInputView2

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    interface ICoreInputView3;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3 ABI::Windows::UI::ViewManagement::Core::ICoreInputView3

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    interface ICoreInputViewOcclusion;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    interface ICoreInputViewOcclusionsChangedEventArgs;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    interface ICoreInputViewStatics;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics ABI::Windows::UI::ViewManagement::Core::ICoreInputViewStatics

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    interface ICoreInputViewStatics2;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2 ABI::Windows::UI::ViewManagement::Core::ICoreInputViewStatics2

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    interface ICoreInputViewTransferringXYFocusEventArgs;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs ABI::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    class CoreInputViewOcclusion;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_USE
#define DEF___FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("5bb57354-4f40-5ef3-a5d1-6a6049f905a1"))
IIterator<ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion*> : IIterator_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion*, ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterator`1<Windows.UI.ViewManagement.Core.CoreInputViewOcclusion>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterator<ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion*> __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_t;
#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion ABI::Windows::Foundation::Collections::__FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion*>
//#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_t ABI::Windows::Foundation::Collections::IIterator<ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_USE
#define DEF___FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("0a11958b-63da-5566-913a-180550dad26a"))
IIterable<ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion*> : IIterable_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion*, ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IIterable`1<Windows.UI.ViewManagement.Core.CoreInputViewOcclusion>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IIterable<ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion*> __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_t;
#define __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion ABI::Windows::Foundation::Collections::__FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion*>
//#define __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_t ABI::Windows::Foundation::Collections::IIterable<ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_USE
#define DEF___FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation { namespace Collections {
template <>
struct __declspec(uuid("e0963578-a246-5680-86d1-27519423e212"))
IVectorView<ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion*> : IVectorView_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion*, ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.Collections.IVectorView`1<Windows.UI.ViewManagement.Core.CoreInputViewOcclusion>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IVectorView<ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusion*> __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_t;
#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion ABI::Windows::Foundation::Collections::__FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_t
/* Collections */ } /* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion*>
//#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_t ABI::Windows::Foundation::Collections::IVectorView<ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusion*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    class CoreInputView;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_USE
#define DEF___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("2bc0e7f6-c772-56e0-9439-650666c78d0c"))
ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::CoreInputView*,IInspectable*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::ViewManagement::Core::CoreInputView*, ABI::Windows::UI::ViewManagement::Core::ICoreInputView*>,IInspectable*> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.UI.ViewManagement.Core.CoreInputView, Object>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::CoreInputView*,IInspectable*> __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_t;
#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::ICoreInputView*,IInspectable*>
//#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::ICoreInputView*,IInspectable*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    class CoreInputViewOcclusionsChangedEventArgs;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef DEF___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("5adecf04-edd1-5133-abc7-582a027f09bb"))
ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::CoreInputView*,ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::ViewManagement::Core::CoreInputView*, ABI::Windows::UI::ViewManagement::Core::ICoreInputView*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs*, ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.UI.ViewManagement.Core.CoreInputView, Windows.UI.ViewManagement.Core.CoreInputViewOcclusionsChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::CoreInputView*,ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionsChangedEventArgs*> __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::ICoreInputView*,ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::ICoreInputView*,ABI::Windows::UI::ViewManagement::Core::ICoreInputViewOcclusionsChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    class CoreInputViewTransferringXYFocusEventArgs;
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("881e8198-7ff6-5cd9-8a64-6dd4292267ad"))
ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::CoreInputView*,ABI::Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::ViewManagement::Core::CoreInputView*, ABI::Windows::UI::ViewManagement::Core::ICoreInputView*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs*, ABI::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.UI.ViewManagement.Core.CoreInputView, Windows.UI.ViewManagement.Core.CoreInputViewTransferringXYFocusEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::CoreInputView*,ABI::Windows::UI::ViewManagement::Core::CoreInputViewTransferringXYFocusEventArgs*> __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_t;
#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::ICoreInputView*,ABI::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs*>
//#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::UI::ViewManagement::Core::ICoreInputView*,ABI::Windows::UI::ViewManagement::Core::ICoreInputViewTransferringXYFocusEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct Rect Rect;
            
        } /* Foundation */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace UI {
            class UIContext;
        } /* UI */
    } /* Windows */} /* ABI */

#ifndef ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace UI {
            interface IUIContext;
        } /* UI */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CUI_CIUIContext ABI::Windows::UI::IUIContext

#endif // ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__




namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    
                    typedef enum CoreInputViewKind : int CoreInputViewKind;
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    
                    typedef enum CoreInputViewOcclusionKind : int CoreInputViewOcclusionKind;
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    
                    typedef enum CoreInputViewXYFocusTransferDirection : int CoreInputViewXYFocusTransferDirection;
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */























/*
 *
 * Struct Windows.UI.ViewManagement.Core.CoreInputViewKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    /* [v1_enum, contract] */
                    enum CoreInputViewKind : int
                    {
                        CoreInputViewKind_Default = 0,
                        CoreInputViewKind_Keyboard = 1,
                        CoreInputViewKind_Handwriting = 2,
                        CoreInputViewKind_Emoji = 3,
                    };
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.UI.ViewManagement.Core.CoreInputViewOcclusionKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    /* [v1_enum, contract] */
                    enum CoreInputViewOcclusionKind : int
                    {
                        CoreInputViewOcclusionKind_Docked = 0,
                        CoreInputViewOcclusionKind_Floating = 1,
                        CoreInputViewOcclusionKind_Overlay = 2,
                    };
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Struct Windows.UI.ViewManagement.Core.CoreInputViewXYFocusTransferDirection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    /* [v1_enum, contract] */
                    enum CoreInputViewXYFocusTransferDirection : int
                    {
                        CoreInputViewXYFocusTransferDirection_Up = 0,
                        CoreInputViewXYFocusTransferDirection_Right = 1,
                        CoreInputViewXYFocusTransferDirection_Down = 2,
                        CoreInputViewXYFocusTransferDirection_Left = 3,
                    };
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputView
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputView
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputView[] = L"Windows.UI.ViewManagement.Core.ICoreInputView";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    /* [object, uuid("C770CD7A-7001-4C32-BF94-25C1F554CBF1"), exclusiveto, contract] */
                    MIDL_INTERFACE("C770CD7A-7001-4C32-BF94-25C1F554CBF1")
                    ICoreInputView : public IInspectable
                    {
                    public:
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_OcclusionsChanged(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_OcclusionsChanged(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE GetCoreInputViewOcclusions(
                            /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryShowPrimaryView(
                            /* [retval, out] */__RPC__out ::boolean * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryHidePrimaryView(
                            /* [retval, out] */__RPC__out ::boolean * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreInputView=_uuidof(ICoreInputView);
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputView2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputView
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputView2[] = L"Windows.UI.ViewManagement.Core.ICoreInputView2";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    /* [object, uuid("0ED726C1-E09A-4AE8-AEDF-DFA4857D1A01"), exclusiveto, contract] */
                    MIDL_INTERFACE("0ED726C1-E09A-4AE8-AEDF-DFA4857D1A01")
                    ICoreInputView2 : public IInspectable
                    {
                    public:
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_XYFocusTransferringFromPrimaryView(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_XYFocusTransferringFromPrimaryView(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_XYFocusTransferredToPrimaryView(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * token
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_XYFocusTransferredToPrimaryView(
                            /* [in] */EventRegistrationToken token
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryTransferXYFocusToPrimaryView(
                            /* [in] */ABI::Windows::Foundation::Rect origin,
                            /* [in] */ABI::Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection direction,
                            /* [retval, out] */__RPC__out ::boolean * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreInputView2=_uuidof(ICoreInputView2);
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputView3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputView
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputView3[] = L"Windows.UI.ViewManagement.Core.ICoreInputView3";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    /* [object, uuid("BC941653-3AB9-4849-8F58-46E7F0353CFC"), exclusiveto, contract] */
                    MIDL_INTERFACE("BC941653-3AB9-4849-8F58-46E7F0353CFC")
                    ICoreInputView3 : public IInspectable
                    {
                    public:
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE TryShow(
                            /* [retval, out] */__RPC__out ::boolean * result
                            ) = 0;
                        /* [overload] */virtual HRESULT STDMETHODCALLTYPE TryShowWithKind(
                            /* [in] */ABI::Windows::UI::ViewManagement::Core::CoreInputViewKind type,
                            /* [retval, out] */__RPC__out ::boolean * result
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE TryHide(
                            /* [retval, out] */__RPC__out ::boolean * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreInputView3=_uuidof(ICoreInputView3);
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputViewOcclusion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputViewOcclusion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusion[] = L"Windows.UI.ViewManagement.Core.ICoreInputViewOcclusion";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    /* [object, uuid("CC36CE06-3865-4177-B5F5-8B65E0B9CE84"), exclusiveto, contract] */
                    MIDL_INTERFACE("CC36CE06-3865-4177-B5F5-8B65E0B9CE84")
                    ICoreInputViewOcclusion : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_OccludingRect(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Rect * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_OcclusionKind(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::ViewManagement::Core::CoreInputViewOcclusionKind * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreInputViewOcclusion=_uuidof(ICoreInputViewOcclusion);
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputViewOcclusionsChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputViewOcclusionsChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusionsChangedEventArgs[] = L"Windows.UI.ViewManagement.Core.ICoreInputViewOcclusionsChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    /* [object, uuid("BE1027E8-B3EE-4DF7-9554-89CDC66082C2"), exclusiveto, contract] */
                    MIDL_INTERFACE("BE1027E8-B3EE-4DF7-9554-89CDC66082C2")
                    ICoreInputViewOcclusionsChangedEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Occlusions(
                            /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Handled(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Handled(
                            /* [in] */::boolean value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreInputViewOcclusionsChangedEventArgs=_uuidof(ICoreInputViewOcclusionsChangedEventArgs);
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputViewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputView
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputViewStatics[] = L"Windows.UI.ViewManagement.Core.ICoreInputViewStatics";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    /* [object, uuid("7D9B97CD-EDBE-49CF-A54F-337DE052907F"), exclusiveto, contract] */
                    MIDL_INTERFACE("7D9B97CD-EDBE-49CF-A54F-337DE052907F")
                    ICoreInputViewStatics : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE GetForCurrentView(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::ViewManagement::Core::ICoreInputView * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreInputViewStatics=_uuidof(ICoreInputViewStatics);
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputViewStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputView
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputViewStatics2[] = L"Windows.UI.ViewManagement.Core.ICoreInputViewStatics2";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    /* [object, uuid("7EBC0862-D049-4E52-87B0-1E90E98C49ED"), exclusiveto, contract] */
                    MIDL_INTERFACE("7EBC0862-D049-4E52-87B0-1E90E98C49ED")
                    ICoreInputViewStatics2 : public IInspectable
                    {
                    public:
                        virtual HRESULT STDMETHODCALLTYPE GetForUIContext(
                            /* [in] */__RPC__in_opt ABI::Windows::UI::IUIContext * context,
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::UI::ViewManagement::Core::ICoreInputView * * result
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreInputViewStatics2=_uuidof(ICoreInputViewStatics2);
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputViewTransferringXYFocusEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputViewTransferringXYFocusEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs[] = L"Windows.UI.ViewManagement.Core.ICoreInputViewTransferringXYFocusEventArgs";
namespace ABI {
    namespace Windows {
        namespace UI {
            namespace ViewManagement {
                namespace Core {
                    /* [object, uuid("04DE169F-BA02-4850-8B55-D82D03BA6D7F"), exclusiveto, contract] */
                    MIDL_INTERFACE("04DE169F-BA02-4850-8B55-D82D03BA6D7F")
                    ICoreInputViewTransferringXYFocusEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Origin(
                            /* [retval, out] */__RPC__out ABI::Windows::Foundation::Rect * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Direction(
                            /* [retval, out] */__RPC__out ABI::Windows::UI::ViewManagement::Core::CoreInputViewXYFocusTransferDirection * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_TransferHandled(
                            /* [in] */::boolean value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_TransferHandled(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_KeepPrimaryViewVisible(
                            /* [in] */::boolean value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_KeepPrimaryViewVisible(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreInputViewTransferringXYFocusEventArgs=_uuidof(ICoreInputViewTransferringXYFocusEventArgs);
                    
                } /* Core */
            } /* ViewManagement */
        } /* UI */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.UI.ViewManagement.Core.CoreInputView
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.ViewManagement.Core.ICoreInputViewStatics2 interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.UI.ViewManagement.Core.ICoreInputViewStatics interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.ViewManagement.Core.ICoreInputView ** Default Interface **
 *    Windows.UI.ViewManagement.Core.ICoreInputView2
 *    Windows.UI.ViewManagement.Core.ICoreInputView3
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputView_DEFINED
#define RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputView_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_ViewManagement_Core_CoreInputView[] = L"Windows.UI.ViewManagement.Core.CoreInputView";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.ViewManagement.Core.CoreInputViewOcclusion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.ViewManagement.Core.ICoreInputViewOcclusion ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewOcclusion_DEFINED
#define RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewOcclusion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_ViewManagement_Core_CoreInputViewOcclusion[] = L"Windows.UI.ViewManagement.Core.CoreInputViewOcclusion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.ViewManagement.Core.CoreInputViewOcclusionsChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.ViewManagement.Core.ICoreInputViewOcclusionsChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewOcclusionsChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewOcclusionsChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_ViewManagement_Core_CoreInputViewOcclusionsChangedEventArgs[] = L"Windows.UI.ViewManagement.Core.CoreInputViewOcclusionsChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.ViewManagement.Core.CoreInputViewTransferringXYFocusEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.ViewManagement.Core.ICoreInputViewTransferringXYFocusEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewTransferringXYFocusEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewTransferringXYFocusEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_ViewManagement_Core_CoreInputViewTransferringXYFocusEventArgs[] = L"Windows.UI.ViewManagement.Core.CoreInputViewTransferringXYFocusEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000





#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView;

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2;

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3 __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3;

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion;

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs;

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics;

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2 __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2;

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs;

#endif // ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_INTERFACE_DEFINED__)
#define ____FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_INTERFACE_DEFINED__

typedef interface __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion;

typedef struct __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This);
    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Current )(__RPC__in __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * *current);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_HasCurrent )(__RPC__in __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *MoveNext )(__RPC__in __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This, /* [retval][out] */ __RPC__out boolean *hasCurrent);
    HRESULT ( STDMETHODCALLTYPE *GetMany )(__RPC__in __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
        /* [in] */ unsigned int capacity,
        /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * *items,
        /* [retval][out] */ __RPC__out unsigned int *actual);

    END_INTERFACE
} __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionVtbl;

interface __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion
{
    CONST_VTBL struct __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_get_Current(This,current)	\
    ( (This)->lpVtbl -> get_Current(This,current) ) 

#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_get_HasCurrent(This,hasCurrent)	\
    ( (This)->lpVtbl -> get_HasCurrent(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_MoveNext(This,hasCurrent)	\
    ( (This)->lpVtbl -> MoveNext(This,hasCurrent) ) 

#define __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetMany(This,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,capacity,items,actual) ) 

#endif /* COBJMACROS */


#endif // ____FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_INTERFACE_DEFINED__)
#define ____FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_INTERFACE_DEFINED__

typedef interface __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion;

typedef  struct __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This);

    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
                                           /* [out] */ __RPC__out ULONG *iidCount,
                                           /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *First )(__RPC__in __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This, /* [retval][out] */ __RPC__deref_out_opt __FIIterator_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion **first);

    END_INTERFACE
} __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionVtbl;

interface __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion
{
    CONST_VTBL struct __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionVtbl *lpVtbl;
};

#ifdef COBJMACROS

#define __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_First(This,first)	\
    ( (This)->lpVtbl -> First(This,first) ) 

#endif /* COBJMACROS */


#endif // ____FIIterable_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_INTERFACE_DEFINED__)
#define ____FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_INTERFACE_DEFINED__

typedef interface __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion;

typedef struct __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);

    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This);

    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);

    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);

    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
        __RPC__in __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);

    HRESULT ( STDMETHODCALLTYPE *GetAt )( 
                                         __RPC__in __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
                                         /* [in] */ unsigned int index,
                                         /* [retval][out] */ __RPC__out __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * *item);

        /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Size )( 
            __RPC__in __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
            /* [retval][out] */ __RPC__out unsigned int *size);

        HRESULT ( STDMETHODCALLTYPE *IndexOf )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
            /* [in] */ __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * item,
            /* [out] */ __RPC__out unsigned int *index,
            /* [retval][out] */ __RPC__out boolean *found);

        HRESULT ( STDMETHODCALLTYPE *GetMany )( 
                                               __RPC__in __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * This,
            /* [in] */ unsigned int startIndex,
            /* [in] */ unsigned int capacity,
            /* [size_is][length_is][out] */ __RPC__out_ecount_part(capacity, *actual) __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * *items,
            /* [retval][out] */ __RPC__out unsigned int *actual);

        END_INTERFACE
} __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionVtbl;

interface __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion
{
    CONST_VTBL struct __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionVtbl *lpVtbl;
};



#ifdef COBJMACROS


#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetAt(This,index,item)	\
    ( (This)->lpVtbl -> GetAt(This,index,item) ) 

#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_get_Size(This,size)	\
    ( (This)->lpVtbl -> get_Size(This,size) ) 

#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_IndexOf(This,item,index,found)	\
    ( (This)->lpVtbl -> IndexOf(This,item,index,found) ) 

#define __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_GetMany(This,startIndex,capacity,items,actual)	\
    ( (This)->lpVtbl -> GetMany(This,startIndex,capacity,items,actual) ) 

#endif /* COBJMACROS */



#endif // ____FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable;

typedef struct __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectableVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * sender,/* [in] */ __RPC__in_opt IInspectable * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectableVtbl;

interface __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectableVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000



#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



typedef struct __x_ABI_CWindows_CFoundation_CRect __x_ABI_CWindows_CFoundation_CRect;




#ifndef ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__
#define ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CUI_CIUIContext __x_ABI_CWindows_CUI_CIUIContext;

#endif // ____x_ABI_CWindows_CUI_CIUIContext_FWD_DEFINED__





typedef enum __x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewKind __x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewKind;


typedef enum __x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewOcclusionKind __x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewOcclusionKind;


typedef enum __x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewXYFocusTransferDirection __x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewXYFocusTransferDirection;























/*
 *
 * Struct Windows.UI.ViewManagement.Core.CoreInputViewKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewKind
{
    CoreInputViewKind_Default = 0,
    CoreInputViewKind_Keyboard = 1,
    CoreInputViewKind_Handwriting = 2,
    CoreInputViewKind_Emoji = 3,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Struct Windows.UI.ViewManagement.Core.CoreInputViewOcclusionKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewOcclusionKind
{
    CoreInputViewOcclusionKind_Docked = 0,
    CoreInputViewOcclusionKind_Floating = 1,
    CoreInputViewOcclusionKind_Overlay = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Struct Windows.UI.ViewManagement.Core.CoreInputViewXYFocusTransferDirection
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewXYFocusTransferDirection
{
    CoreInputViewXYFocusTransferDirection_Up = 0,
    CoreInputViewXYFocusTransferDirection_Right = 1,
    CoreInputViewXYFocusTransferDirection_Down = 2,
    CoreInputViewXYFocusTransferDirection_Left = 3,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputView
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputView
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputView[] = L"Windows.UI.ViewManagement.Core.ICoreInputView";
/* [object, uuid("C770CD7A-7001-4C32-BF94-25C1F554CBF1"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_OcclusionsChanged )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusionsChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_OcclusionsChanged )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * This,
        /* [in] */EventRegistrationToken token
        );
    HRESULT ( STDMETHODCALLTYPE *GetCoreInputViewOcclusions )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryShowPrimaryView )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * This,
        /* [retval, out] */__RPC__out boolean * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryHidePrimaryView )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * This,
        /* [retval, out] */__RPC__out boolean * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewVtbl;

interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_add_OcclusionsChanged(This,handler,token) \
    ( (This)->lpVtbl->add_OcclusionsChanged(This,handler,token) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_remove_OcclusionsChanged(This,token) \
    ( (This)->lpVtbl->remove_OcclusionsChanged(This,token) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_GetCoreInputViewOcclusions(This,result) \
    ( (This)->lpVtbl->GetCoreInputViewOcclusions(This,result) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_TryShowPrimaryView(This,result) \
    ( (This)->lpVtbl->TryShowPrimaryView(This,result) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_TryHidePrimaryView(This,result) \
    ( (This)->lpVtbl->TryHidePrimaryView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputView2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputView
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputView2[] = L"Windows.UI.ViewManagement.Core.ICoreInputView2";
/* [object, uuid("0ED726C1-E09A-4AE8-AEDF-DFA4857D1A01"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_XYFocusTransferringFromPrimaryView )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_Windows__CUI__CViewManagement__CCore__CCoreInputViewTransferringXYFocusEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_XYFocusTransferringFromPrimaryView )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 * This,
        /* [in] */EventRegistrationToken token
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_XYFocusTransferredToPrimaryView )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CUI__CViewManagement__CCore__CCoreInputView_IInspectable * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * token
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_XYFocusTransferredToPrimaryView )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 * This,
        /* [in] */EventRegistrationToken token
        );
    HRESULT ( STDMETHODCALLTYPE *TryTransferXYFocusToPrimaryView )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2 * This,
        /* [in] */__x_ABI_CWindows_CFoundation_CRect origin,
        /* [in] */__x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewXYFocusTransferDirection direction,
        /* [retval, out] */__RPC__out boolean * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2Vtbl;

interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_add_XYFocusTransferringFromPrimaryView(This,handler,token) \
    ( (This)->lpVtbl->add_XYFocusTransferringFromPrimaryView(This,handler,token) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_remove_XYFocusTransferringFromPrimaryView(This,token) \
    ( (This)->lpVtbl->remove_XYFocusTransferringFromPrimaryView(This,token) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_add_XYFocusTransferredToPrimaryView(This,handler,token) \
    ( (This)->lpVtbl->add_XYFocusTransferredToPrimaryView(This,handler,token) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_remove_XYFocusTransferredToPrimaryView(This,token) \
    ( (This)->lpVtbl->remove_XYFocusTransferredToPrimaryView(This,token) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_TryTransferXYFocusToPrimaryView(This,origin,direction,result) \
    ( (This)->lpVtbl->TryTransferXYFocusToPrimaryView(This,origin,direction,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputView3
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 7.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputView
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputView3[] = L"Windows.UI.ViewManagement.Core.ICoreInputView3";
/* [object, uuid("BC941653-3AB9-4849-8F58-46E7F0353CFC"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [overload] */HRESULT ( STDMETHODCALLTYPE *TryShow )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3 * This,
        /* [retval, out] */__RPC__out boolean * result
        );
    /* [overload] */HRESULT ( STDMETHODCALLTYPE *TryShowWithKind )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3 * This,
        /* [in] */__x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewKind type,
        /* [retval, out] */__RPC__out boolean * result
        );
    HRESULT ( STDMETHODCALLTYPE *TryHide )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3 * This,
        /* [retval, out] */__RPC__out boolean * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3Vtbl;

interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_TryShow(This,result) \
    ( (This)->lpVtbl->TryShow(This,result) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_TryShowWithKind(This,type,result) \
    ( (This)->lpVtbl->TryShowWithKind(This,type,result) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_TryHide(This,result) \
    ( (This)->lpVtbl->TryHide(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView3_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x70000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputViewOcclusion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputViewOcclusion
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusion[] = L"Windows.UI.ViewManagement.Core.ICoreInputViewOcclusion";
/* [object, uuid("CC36CE06-3865-4177-B5F5-8B65E0B9CE84"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_OccludingRect )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CRect * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_OcclusionKind )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewOcclusionKind * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionVtbl;

interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_get_OccludingRect(This,value) \
    ( (This)->lpVtbl->get_OccludingRect(This,value) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_get_OcclusionKind(This,value) \
    ( (This)->lpVtbl->get_OcclusionKind(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusion_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputViewOcclusionsChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputViewOcclusionsChangedEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputViewOcclusionsChangedEventArgs[] = L"Windows.UI.ViewManagement.Core.ICoreInputViewOcclusionsChangedEventArgs";
/* [object, uuid("BE1027E8-B3EE-4DF7-9554-89CDC66082C2"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Occlusions )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt __FIVectorView_1_Windows__CUI__CViewManagement__CCore__CCoreInputViewOcclusion * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Handled )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Handled )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs * This,
        /* [in] */boolean value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgsVtbl;

interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_get_Occlusions(This,value) \
    ( (This)->lpVtbl->get_Occlusions(This,value) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_get_Handled(This,value) \
    ( (This)->lpVtbl->get_Handled(This,value) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_put_Handled(This,value) \
    ( (This)->lpVtbl->put_Handled(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewOcclusionsChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputViewStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputView
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputViewStatics[] = L"Windows.UI.ViewManagement.Core.ICoreInputViewStatics";
/* [object, uuid("7D9B97CD-EDBE-49CF-A54F-337DE052907F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetForCurrentView )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStaticsVtbl;

interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_GetForCurrentView(This,result) \
    ( (This)->lpVtbl->GetForCurrentView(This,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputViewStatics2
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 8.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputView
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputViewStatics2[] = L"Windows.UI.ViewManagement.Core.ICoreInputViewStatics2";
/* [object, uuid("7EBC0862-D049-4E52-87B0-1E90E98C49ED"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2 * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2 * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2 * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2 * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2 * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2 * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetForUIContext )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2 * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CUI_CIUIContext * context,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputView * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2Vtbl;

interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_GetForUIContext(This,context,result) \
    ( (This)->lpVtbl->GetForUIContext(This,context,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewStatics2_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x80000


/*
 *
 * Interface Windows.UI.ViewManagement.Core.ICoreInputViewTransferringXYFocusEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.UI.ViewManagement.Core.CoreInputViewTransferringXYFocusEventArgs
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_UI_ViewManagement_Core_ICoreInputViewTransferringXYFocusEventArgs[] = L"Windows.UI.ViewManagement.Core.ICoreInputViewTransferringXYFocusEventArgs";
/* [object, uuid("04DE169F-BA02-4850-8B55-D82D03BA6D7F"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Origin )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CRect * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Direction )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CUI_CViewManagement_CCore_CCoreInputViewXYFocusTransferDirection * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_TransferHandled )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_TransferHandled )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_KeepPrimaryViewVisible )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_KeepPrimaryViewVisible )(
        __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgsVtbl;

interface __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_get_Origin(This,value) \
    ( (This)->lpVtbl->get_Origin(This,value) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_get_Direction(This,value) \
    ( (This)->lpVtbl->get_Direction(This,value) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_put_TransferHandled(This,value) \
    ( (This)->lpVtbl->put_TransferHandled(This,value) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_get_TransferHandled(This,value) \
    ( (This)->lpVtbl->get_TransferHandled(This,value) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_put_KeepPrimaryViewVisible(This,value) \
    ( (This)->lpVtbl->put_KeepPrimaryViewVisible(This,value) )

#define __x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_get_KeepPrimaryViewVisible(This,value) \
    ( (This)->lpVtbl->get_KeepPrimaryViewVisible(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs;
#endif /* !defined(____x_ABI_CWindows_CUI_CViewManagement_CCore_CICoreInputViewTransferringXYFocusEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.UI.ViewManagement.Core.CoreInputView
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.UI.ViewManagement.Core.ICoreInputViewStatics2 interface starting with version 8.0 of the Windows.Foundation.UniversalApiContract API contract
 *   Static Methods exist on the Windows.UI.ViewManagement.Core.ICoreInputViewStatics interface starting with version 5.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.UI.ViewManagement.Core.ICoreInputView ** Default Interface **
 *    Windows.UI.ViewManagement.Core.ICoreInputView2
 *    Windows.UI.ViewManagement.Core.ICoreInputView3
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputView_DEFINED
#define RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputView_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_ViewManagement_Core_CoreInputView[] = L"Windows.UI.ViewManagement.Core.CoreInputView";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.ViewManagement.Core.CoreInputViewOcclusion
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.ViewManagement.Core.ICoreInputViewOcclusion ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewOcclusion_DEFINED
#define RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewOcclusion_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_ViewManagement_Core_CoreInputViewOcclusion[] = L"Windows.UI.ViewManagement.Core.CoreInputViewOcclusion";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.ViewManagement.Core.CoreInputViewOcclusionsChangedEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 5.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.ViewManagement.Core.ICoreInputViewOcclusionsChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000

#ifndef RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewOcclusionsChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewOcclusionsChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_ViewManagement_Core_CoreInputViewOcclusionsChangedEventArgs[] = L"Windows.UI.ViewManagement.Core.CoreInputViewOcclusionsChangedEventArgs";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x50000


/*
 *
 * Class Windows.UI.ViewManagement.Core.CoreInputViewTransferringXYFocusEventArgs
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.UI.ViewManagement.Core.ICoreInputViewTransferringXYFocusEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewTransferringXYFocusEventArgs_DEFINED
#define RUNTIMECLASS_Windows_UI_ViewManagement_Core_CoreInputViewTransferringXYFocusEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_UI_ViewManagement_Core_CoreInputViewTransferringXYFocusEventArgs[] = L"Windows.UI.ViewManagement.Core.CoreInputViewTransferringXYFocusEventArgs";
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
#endif // __windows2Eui2Eviewmanagement2Ecore_p_h__

#endif // __windows2Eui2Eviewmanagement2Ecore_h__
