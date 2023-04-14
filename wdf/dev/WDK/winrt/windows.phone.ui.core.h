/* Header file automatically generated from windows.phone.ui.core.idl */
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
#ifndef __windows2Ephone2Eui2Ecore_h__
#define __windows2Ephone2Eui2Ecore_h__
#ifndef __windows2Ephone2Eui2Ecore_p_h__
#define __windows2Ephone2Eui2Ecore_p_h__


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
#include "Windows.Phone.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    interface ICoreSelectionChangedEventArgs;
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs ABI::Windows::Phone::UI::Core::ICoreSelectionChangedEventArgs

#endif // ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    interface ICoreTextChangedEventArgs;
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs ABI::Windows::Phone::UI::Core::ICoreTextChangedEventArgs

#endif // ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    interface ICoreWindowKeyboardInput;
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput ABI::Windows::Phone::UI::Core::ICoreWindowKeyboardInput

#endif // ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    interface IKeyboardInputBuffer;
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer ABI::Windows::Phone::UI::Core::IKeyboardInputBuffer

#endif // ____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    class KeyboardInputBuffer;
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */


namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    class CoreSelectionChangedEventArgs;
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */


#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("9614b92d-f6bc-5414-8940-6245f1077239"))
ITypedEventHandler<ABI::Windows::Phone::UI::Core::KeyboardInputBuffer*,ABI::Windows::Phone::UI::Core::CoreSelectionChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Phone::UI::Core::KeyboardInputBuffer*, ABI::Windows::Phone::UI::Core::IKeyboardInputBuffer*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Phone::UI::Core::CoreSelectionChangedEventArgs*, ABI::Windows::Phone::UI::Core::ICoreSelectionChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Phone.UI.Core.KeyboardInputBuffer, Windows.Phone.UI.Core.CoreSelectionChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Phone::UI::Core::KeyboardInputBuffer*,ABI::Windows::Phone::UI::Core::CoreSelectionChangedEventArgs*> __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Phone::UI::Core::IKeyboardInputBuffer*,ABI::Windows::Phone::UI::Core::ICoreSelectionChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Phone::UI::Core::IKeyboardInputBuffer*,ABI::Windows::Phone::UI::Core::ICoreSelectionChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_USE */


#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    class CoreTextChangedEventArgs;
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */


#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000

#ifndef DEF___FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_USE
#define DEF___FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("10825382-310b-5cb4-817b-3532bd239ac7"))
ITypedEventHandler<ABI::Windows::Phone::UI::Core::KeyboardInputBuffer*,ABI::Windows::Phone::UI::Core::CoreTextChangedEventArgs*> : ITypedEventHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Phone::UI::Core::KeyboardInputBuffer*, ABI::Windows::Phone::UI::Core::IKeyboardInputBuffer*>,ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Phone::UI::Core::CoreTextChangedEventArgs*, ABI::Windows::Phone::UI::Core::ICoreTextChangedEventArgs*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.TypedEventHandler`2<Windows.Phone.UI.Core.KeyboardInputBuffer, Windows.Phone.UI.Core.CoreTextChangedEventArgs>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef ITypedEventHandler<ABI::Windows::Phone::UI::Core::KeyboardInputBuffer*,ABI::Windows::Phone::UI::Core::CoreTextChangedEventArgs*> __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_t;
#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs ABI::Windows::Foundation::__FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Phone::UI::Core::IKeyboardInputBuffer*,ABI::Windows::Phone::UI::Core::ICoreTextChangedEventArgs*>
//#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_t ABI::Windows::Foundation::ITypedEventHandler<ABI::Windows::Phone::UI::Core::IKeyboardInputBuffer*,ABI::Windows::Phone::UI::Core::ICoreTextChangedEventArgs*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_USE */


#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000






namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    
                    typedef enum CoreInputScope : int CoreInputScope;
                    
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */


















/*
 *
 * Struct Windows.Phone.UI.Core.CoreInputScope
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 */

#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    /* [v1_enum, contract] */
                    enum CoreInputScope : int
                    {
                        CoreInputScope_Default = 0,
                        CoreInputScope_Url = 1,
                        CoreInputScope_EmailSmtpAddress = 5,
                        CoreInputScope_Number = 29,
                        CoreInputScope_TelephoneNumber = 32,
                        CoreInputScope_Text = 49,
                        CoreInputScope_Search = 51,
                    };
                    
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.UI.Core.ICoreSelectionChangedEventArgs
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Phone.UI.Core.CoreSelectionChangedEventArgs
 *
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_UI_Core_ICoreSelectionChangedEventArgs[] = L"Windows.Phone.UI.Core.ICoreSelectionChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    /* [object, uuid("C2941949-3955-4EC2-8F88-3F2BFC04D0F1"), exclusiveto, contract] */
                    MIDL_INTERFACE("C2941949-3955-4EC2-8F88-3F2BFC04D0F1")
                    ICoreSelectionChangedEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Start(
                            /* [retval, out] */__RPC__out UINT32 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Length(
                            /* [retval, out] */__RPC__out UINT32 * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreSelectionChangedEventArgs=_uuidof(ICoreSelectionChangedEventArgs);
                    
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.UI.Core.ICoreTextChangedEventArgs
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Phone.UI.Core.CoreTextChangedEventArgs
 *
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_UI_Core_ICoreTextChangedEventArgs[] = L"Windows.Phone.UI.Core.ICoreTextChangedEventArgs";
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    /* [object, uuid("7E3C9572-60E4-4FEB-8683-4CF0E0FA7659"), exclusiveto, contract] */
                    MIDL_INTERFACE("7E3C9572-60E4-4FEB-8683-4CF0E0FA7659")
                    ICoreTextChangedEventArgs : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Start(
                            /* [retval, out] */__RPC__out UINT32 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_OldLength(
                            /* [retval, out] */__RPC__out UINT32 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NewText(
                            /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreTextChangedEventArgs=_uuidof(ICoreTextChangedEventArgs);
                    
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.UI.Core.ICoreWindowKeyboardInput
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_UI_Core_ICoreWindowKeyboardInput[] = L"Windows.Phone.UI.Core.ICoreWindowKeyboardInput";
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    /* [object, uuid("196B175E-1A33-4B17-9935-338EF6443477"), contract] */
                    MIDL_INTERFACE("196B175E-1A33-4B17-9935-338EF6443477")
                    ICoreWindowKeyboardInput : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_IsKeyboardInputEnabled(
                            /* [retval, out] */__RPC__out ::boolean * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_IsKeyboardInputEnabled(
                            /* [in] */::boolean value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_KeyboardInputBuffer(
                            /* [retval, out] */__RPC__deref_out_opt ABI::Windows::Phone::UI::Core::IKeyboardInputBuffer * * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_KeyboardInputBuffer(
                            /* [in] */__RPC__in_opt ABI::Windows::Phone::UI::Core::IKeyboardInputBuffer * value
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_ICoreWindowKeyboardInput=_uuidof(ICoreWindowKeyboardInput);
                    
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput;
#endif /* !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.UI.Core.IKeyboardInputBuffer
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Phone.UI.Core.KeyboardInputBuffer
 *
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_UI_Core_IKeyboardInputBuffer[] = L"Windows.Phone.UI.Core.IKeyboardInputBuffer";
namespace ABI {
    namespace Windows {
        namespace Phone {
            namespace UI {
                namespace Core {
                    /* [object, uuid("3776EE93-8079-40CC-8C2F-A7A997CF9D6E"), exclusiveto, contract] */
                    MIDL_INTERFACE("3776EE93-8079-40CC-8C2F-A7A997CF9D6E")
                    IKeyboardInputBuffer : public IInspectable
                    {
                    public:
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_Text(
                            /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_Text(
                            /* [in] */__RPC__in HSTRING value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SelectionStart(
                            /* [retval, out] */__RPC__out UINT32 * value
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_SelectionLength(
                            /* [retval, out] */__RPC__out UINT32 * value
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE Select(
                            /* [in] */UINT32 start,
                            /* [in] */UINT32 length
                            ) = 0;
                        virtual HRESULT STDMETHODCALLTYPE SelectFromTap(
                            /* [in] */UINT32 characterIndex
                            ) = 0;
                        /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_InputScope(
                            /* [retval, out] */__RPC__out ABI::Windows::Phone::UI::Core::CoreInputScope * value
                            ) = 0;
                        /* [propput] */virtual HRESULT STDMETHODCALLTYPE put_InputScope(
                            /* [in] */ABI::Windows::Phone::UI::Core::CoreInputScope value
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_TextChanged(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * cookie
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_TextChanged(
                            /* [in] */EventRegistrationToken cookie
                            ) = 0;
                        /* [eventadd] */virtual HRESULT STDMETHODCALLTYPE add_SelectionChanged(
                            /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs * handler,
                            /* [retval, out] */__RPC__out EventRegistrationToken * cookie
                            ) = 0;
                        /* [eventremove] */virtual HRESULT STDMETHODCALLTYPE remove_SelectionChanged(
                            /* [in] */EventRegistrationToken cookie
                            ) = 0;
                        
                    };

                    extern MIDL_CONST_ID IID & IID_IKeyboardInputBuffer=_uuidof(IKeyboardInputBuffer);
                    
                } /* Core */
            } /* UI */
        } /* Phone */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer;
#endif /* !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Phone.UI.Core.CoreSelectionChangedEventArgs
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Phone.UI.Core.ICoreSelectionChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Phone_UI_Core_CoreSelectionChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Phone_UI_Core_CoreSelectionChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Phone_UI_Core_CoreSelectionChangedEventArgs[] = L"Windows.Phone.UI.Core.CoreSelectionChangedEventArgs";
#endif
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Phone.UI.Core.CoreTextChangedEventArgs
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Phone.UI.Core.ICoreTextChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Phone_UI_Core_CoreTextChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Phone_UI_Core_CoreTextChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Phone_UI_Core_CoreTextChangedEventArgs[] = L"Windows.Phone.UI.Core.CoreTextChangedEventArgs";
#endif
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Phone.UI.Core.KeyboardInputBuffer
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Phone.PhoneInternalContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Phone.UI.Core.IKeyboardInputBuffer ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Phone_UI_Core_KeyboardInputBuffer_DEFINED
#define RUNTIMECLASS_Windows_Phone_UI_Core_KeyboardInputBuffer_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Phone_UI_Core_KeyboardInputBuffer[] = L"Windows.Phone.UI.Core.KeyboardInputBuffer";
#endif
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000





#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs;

#endif // ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs;

#endif // ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput;

#endif // ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_FWD_DEFINED__
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer;

#endif // ____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions


#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000



#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if !defined(____FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_INTERFACE_DEFINED__)
#define ____FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_INTERFACE_DEFINED__

typedef interface __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs;

typedef struct __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs * This,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * sender,/* [in] */ __RPC__in_opt __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs * e);
    END_INTERFACE
} __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgsVtbl;

interface __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs
{
    CONST_VTBL struct __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_Invoke(This,sender,e)	\
    ( (This)->lpVtbl -> Invoke(This,sender,e) ) 
#endif /* COBJMACROS */



#endif // ____FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs_INTERFACE_DEFINED__

#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000






typedef enum __x_ABI_CWindows_CPhone_CUI_CCore_CCoreInputScope __x_ABI_CWindows_CPhone_CUI_CCore_CCoreInputScope;


















/*
 *
 * Struct Windows.Phone.UI.Core.CoreInputScope
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 */

#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CPhone_CUI_CCore_CCoreInputScope
{
    CoreInputScope_Default = 0,
    CoreInputScope_Url = 1,
    CoreInputScope_EmailSmtpAddress = 5,
    CoreInputScope_Number = 29,
    CoreInputScope_TelephoneNumber = 32,
    CoreInputScope_Text = 49,
    CoreInputScope_Search = 51,
};
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.UI.Core.ICoreSelectionChangedEventArgs
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Phone.UI.Core.CoreSelectionChangedEventArgs
 *
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_UI_Core_ICoreSelectionChangedEventArgs[] = L"Windows.Phone.UI.Core.ICoreSelectionChangedEventArgs";
/* [object, uuid("C2941949-3955-4EC2-8F88-3F2BFC04D0F1"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Start )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Length )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgsVtbl;

interface __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_get_Start(This,value) \
    ( (This)->lpVtbl->get_Start(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_get_Length(This,value) \
    ( (This)->lpVtbl->get_Length(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreSelectionChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.UI.Core.ICoreTextChangedEventArgs
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Phone.UI.Core.CoreTextChangedEventArgs
 *
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_UI_Core_ICoreTextChangedEventArgs[] = L"Windows.Phone.UI.Core.ICoreTextChangedEventArgs";
/* [object, uuid("7E3C9572-60E4-4FEB-8683-4CF0E0FA7659"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Start )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_OldLength )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NewText )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgsVtbl;

interface __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs
{
    CONST_VTBL struct __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_get_Start(This,value) \
    ( (This)->lpVtbl->get_Start(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_get_OldLength(This,value) \
    ( (This)->lpVtbl->get_OldLength(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_get_NewText(This,value) \
    ( (This)->lpVtbl->get_NewText(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs;
#endif /* !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreTextChangedEventArgs_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.UI.Core.ICoreWindowKeyboardInput
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_UI_Core_ICoreWindowKeyboardInput[] = L"Windows.Phone.UI.Core.ICoreWindowKeyboardInput";
/* [object, uuid("196B175E-1A33-4B17-9935-338EF6443477"), contract] */
typedef struct __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInputVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_IsKeyboardInputEnabled )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput * This,
        /* [retval, out] */__RPC__out boolean * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_IsKeyboardInputEnabled )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput * This,
        /* [in] */boolean value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_KeyboardInputBuffer )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput * This,
        /* [retval, out] */__RPC__deref_out_opt __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_KeyboardInputBuffer )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput * This,
        /* [in] */__RPC__in_opt __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * value
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInputVtbl;

interface __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput
{
    CONST_VTBL struct __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInputVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_get_IsKeyboardInputEnabled(This,value) \
    ( (This)->lpVtbl->get_IsKeyboardInputEnabled(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_put_IsKeyboardInputEnabled(This,value) \
    ( (This)->lpVtbl->put_IsKeyboardInputEnabled(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_get_KeyboardInputBuffer(This,value) \
    ( (This)->lpVtbl->get_KeyboardInputBuffer(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_put_KeyboardInputBuffer(This,value) \
    ( (This)->lpVtbl->put_KeyboardInputBuffer(This,value) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput;
#endif /* !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CICoreWindowKeyboardInput_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Interface Windows.Phone.UI.Core.IKeyboardInputBuffer
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * Interface is a part of the implementation of type Windows.Phone.UI.Core.KeyboardInputBuffer
 *
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000
#if !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Phone_UI_Core_IKeyboardInputBuffer[] = L"Windows.Phone.UI.Core.IKeyboardInputBuffer";
/* [object, uuid("3776EE93-8079-40CC-8C2F-A7A997CF9D6E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBufferVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_Text )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_Text )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [in] */__RPC__in HSTRING value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SelectionStart )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_SelectionLength )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    HRESULT ( STDMETHODCALLTYPE *Select )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [in] */UINT32 start,
        /* [in] */UINT32 length
        );
    HRESULT ( STDMETHODCALLTYPE *SelectFromTap )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [in] */UINT32 characterIndex
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_InputScope )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CPhone_CUI_CCore_CCoreInputScope * value
        );
    /* [propput] */HRESULT ( STDMETHODCALLTYPE *put_InputScope )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [in] */__x_ABI_CWindows_CPhone_CUI_CCore_CCoreInputScope value
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_TextChanged )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreTextChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * cookie
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_TextChanged )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [in] */EventRegistrationToken cookie
        );
    /* [eventadd] */HRESULT ( STDMETHODCALLTYPE *add_SelectionChanged )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [in] */__RPC__in_opt __FITypedEventHandler_2_Windows__CPhone__CUI__CCore__CKeyboardInputBuffer_Windows__CPhone__CUI__CCore__CCoreSelectionChangedEventArgs * handler,
        /* [retval, out] */__RPC__out EventRegistrationToken * cookie
        );
    /* [eventremove] */HRESULT ( STDMETHODCALLTYPE *remove_SelectionChanged )(
        __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer * This,
        /* [in] */EventRegistrationToken cookie
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBufferVtbl;

interface __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer
{
    CONST_VTBL struct __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBufferVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_get_Text(This,value) \
    ( (This)->lpVtbl->get_Text(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_put_Text(This,value) \
    ( (This)->lpVtbl->put_Text(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_get_SelectionStart(This,value) \
    ( (This)->lpVtbl->get_SelectionStart(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_get_SelectionLength(This,value) \
    ( (This)->lpVtbl->get_SelectionLength(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_Select(This,start,length) \
    ( (This)->lpVtbl->Select(This,start,length) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_SelectFromTap(This,characterIndex) \
    ( (This)->lpVtbl->SelectFromTap(This,characterIndex) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_get_InputScope(This,value) \
    ( (This)->lpVtbl->get_InputScope(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_put_InputScope(This,value) \
    ( (This)->lpVtbl->put_InputScope(This,value) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_add_TextChanged(This,handler,cookie) \
    ( (This)->lpVtbl->add_TextChanged(This,handler,cookie) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_remove_TextChanged(This,cookie) \
    ( (This)->lpVtbl->remove_TextChanged(This,cookie) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_add_SelectionChanged(This,handler,cookie) \
    ( (This)->lpVtbl->add_SelectionChanged(This,handler,cookie) )

#define __x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_remove_SelectionChanged(This,cookie) \
    ( (This)->lpVtbl->remove_SelectionChanged(This,cookie) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer;
#endif /* !defined(____x_ABI_CWindows_CPhone_CUI_CCore_CIKeyboardInputBuffer_INTERFACE_DEFINED__) */
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Phone.UI.Core.CoreSelectionChangedEventArgs
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Phone.UI.Core.ICoreSelectionChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Phone_UI_Core_CoreSelectionChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Phone_UI_Core_CoreSelectionChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Phone_UI_Core_CoreSelectionChangedEventArgs[] = L"Windows.Phone.UI.Core.CoreSelectionChangedEventArgs";
#endif
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Phone.UI.Core.CoreTextChangedEventArgs
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * Class implements the following interfaces:
 *    Windows.Phone.UI.Core.ICoreTextChangedEventArgs ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Phone_UI_Core_CoreTextChangedEventArgs_DEFINED
#define RUNTIMECLASS_Windows_Phone_UI_Core_CoreTextChangedEventArgs_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Phone_UI_Core_CoreTextChangedEventArgs[] = L"Windows.Phone.UI.Core.CoreTextChangedEventArgs";
#endif
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000


/*
 *
 * Class Windows.Phone.UI.Core.KeyboardInputBuffer
 *
 * Introduced to Windows.Phone.PhoneInternalContract in version 1.0
 *
 *
 * RuntimeClass can be activated.
 *   Type can be activated via RoActivateInstance starting with version 1.0 of the Windows.Phone.PhoneInternalContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Phone.UI.Core.IKeyboardInputBuffer ** Default Interface **
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000

#ifndef RUNTIMECLASS_Windows_Phone_UI_Core_KeyboardInputBuffer_DEFINED
#define RUNTIMECLASS_Windows_Phone_UI_Core_KeyboardInputBuffer_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Phone_UI_Core_KeyboardInputBuffer[] = L"Windows.Phone.UI.Core.KeyboardInputBuffer";
#endif
#endif // WINDOWS_PHONE_PHONEINTERNALCONTRACT_VERSION >= 0x10000





#endif // defined(__cplusplus)
#pragma pop_macro("MIDL_CONST_ID")
// Restore the original value of the 'DEPRECATED' macro
#pragma pop_macro("DEPRECATED")

#ifdef __clang__
#pragma clang diagnostic pop // deprecated-declarations
#else
#pragma warning(pop)
#endif
#endif // __windows2Ephone2Eui2Ecore_p_h__

#endif // __windows2Ephone2Eui2Ecore_h__
