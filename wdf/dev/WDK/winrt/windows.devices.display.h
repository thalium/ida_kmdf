/* Header file automatically generated from windows.devices.display.idl */
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
#ifndef __windows2Edevices2Edisplay_h__
#define __windows2Edevices2Edisplay_h__
#ifndef __windows2Edevices2Edisplay_p_h__
#define __windows2Edevices2Edisplay_p_h__


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
#include "Windows.Graphics.h"
// Importing Collections header
#include <windows.foundation.collections.h>

#if defined(__cplusplus) && !defined(CINTERFACE)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                interface IDisplayMonitor;
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor ABI::Windows::Devices::Display::IDisplayMonitor

#endif // ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                interface IDisplayMonitorStatics;
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics ABI::Windows::Devices::Display::IDisplayMonitorStatics

#endif // ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                class DisplayMonitor;
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_USE
#define DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("620f34a8-5dba-59df-b719-99b77970344c"))
IAsyncOperationCompletedHandler<ABI::Windows::Devices::Display::DisplayMonitor*> : IAsyncOperationCompletedHandler_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Display::DisplayMonitor*, ABI::Windows::Devices::Display::IDisplayMonitor*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.AsyncOperationCompletedHandler`1<Windows.Devices.Display.DisplayMonitor>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperationCompletedHandler<ABI::Windows::Devices::Display::DisplayMonitor*> __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_t;
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor ABI::Windows::Foundation::__FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Devices::Display::IDisplayMonitor*>
//#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_t ABI::Windows::Foundation::IAsyncOperationCompletedHandler<ABI::Windows::Devices::Display::IDisplayMonitor*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef DEF___FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_USE
#define DEF___FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("28c0e623-4e46-58c3-ad82-502bdecc4345"))
IAsyncOperation<ABI::Windows::Devices::Display::DisplayMonitor*> : IAsyncOperation_impl<ABI::Windows::Foundation::Internal::AggregateType<ABI::Windows::Devices::Display::DisplayMonitor*, ABI::Windows::Devices::Display::IDisplayMonitor*>> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IAsyncOperation`1<Windows.Devices.Display.DisplayMonitor>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IAsyncOperation<ABI::Windows::Devices::Display::DisplayMonitor*> __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_t;
#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor ABI::Windows::Foundation::__FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Devices::Display::IDisplayMonitor*>
//#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_t ABI::Windows::Foundation::IAsyncOperation<ABI::Windows::Devices::Display::IDisplayMonitor*>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_USE */


#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

namespace ABI {
    namespace Windows {
        namespace Foundation {
            struct Size;
            
        } /* Foundation */
    } /* Windows */} /* ABI */


#ifndef DEF___FIReference_1_Windows__CFoundation__CSize_USE
#define DEF___FIReference_1_Windows__CFoundation__CSize_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("61723086-8e53-5276-9f36-2a4bb93e2b75"))
IReference<struct ABI::Windows::Foundation::Size> : IReference_impl<struct ABI::Windows::Foundation::Size> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Windows.Foundation.Size>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<struct ABI::Windows::Foundation::Size> __FIReference_1_Windows__CFoundation__CSize_t;
#define __FIReference_1_Windows__CFoundation__CSize ABI::Windows::Foundation::__FIReference_1_Windows__CFoundation__CSize_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_Windows__CFoundation__CSize ABI::Windows::Foundation::IReference<ABI::Windows::Foundation::Size>
//#define __FIReference_1_Windows__CFoundation__CSize_t ABI::Windows::Foundation::IReference<ABI::Windows::Foundation::Size>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_Windows__CFoundation__CSize_USE */





namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct Point Point;
            
        } /* Foundation */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Foundation {
            
            typedef struct Size Size;
            
        } /* Foundation */
    } /* Windows */} /* ABI */




namespace ABI {
    namespace Windows {
        namespace Graphics {
            
            typedef struct DisplayAdapterId DisplayAdapterId;
            
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            
            typedef struct SizeInt32 SizeInt32;
            
        } /* Graphics */
    } /* Windows */} /* ABI */



namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                
                typedef enum DisplayMonitorConnectionKind : int DisplayMonitorConnectionKind;
                
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                
                typedef enum DisplayMonitorDescriptorKind : int DisplayMonitorDescriptorKind;
                
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                
                typedef enum DisplayMonitorPhysicalConnectorKind : int DisplayMonitorPhysicalConnectorKind;
                
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                
                typedef enum DisplayMonitorUsageKind : int DisplayMonitorUsageKind;
                
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */












/*
 *
 * Struct Windows.Devices.Display.DisplayMonitorConnectionKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                /* [v1_enum, contract] */
                enum DisplayMonitorConnectionKind : int
                {
                    DisplayMonitorConnectionKind_Internal = 0,
                    DisplayMonitorConnectionKind_Wired = 1,
                    DisplayMonitorConnectionKind_Wireless = 2,
                    DisplayMonitorConnectionKind_Virtual = 3,
                };
                
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Devices.Display.DisplayMonitorDescriptorKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                /* [v1_enum, contract] */
                enum DisplayMonitorDescriptorKind : int
                {
                    DisplayMonitorDescriptorKind_Edid = 0,
                    DisplayMonitorDescriptorKind_DisplayId = 1,
                };
                
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Devices.Display.DisplayMonitorPhysicalConnectorKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                /* [v1_enum, contract] */
                enum DisplayMonitorPhysicalConnectorKind : int
                {
                    DisplayMonitorPhysicalConnectorKind_Unknown = 0,
                    DisplayMonitorPhysicalConnectorKind_HD15 = 1,
                    DisplayMonitorPhysicalConnectorKind_AnalogTV = 2,
                    DisplayMonitorPhysicalConnectorKind_Dvi = 3,
                    DisplayMonitorPhysicalConnectorKind_Hdmi = 4,
                    DisplayMonitorPhysicalConnectorKind_Lvds = 5,
                    DisplayMonitorPhysicalConnectorKind_Sdi = 6,
                    DisplayMonitorPhysicalConnectorKind_DisplayPort = 7,
                };
                
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Devices.Display.DisplayMonitorUsageKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                /* [v1_enum, contract] */
                enum DisplayMonitorUsageKind : int
                {
                    DisplayMonitorUsageKind_Standard = 0,
                    DisplayMonitorUsageKind_HeadMounted = 1,
                    DisplayMonitorUsageKind_SpecialPurpose = 2,
                };
                
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Display.IDisplayMonitor
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Display.DisplayMonitor
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Display_IDisplayMonitor[] = L"Windows.Devices.Display.IDisplayMonitor";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                /* [object, uuid("1F6B15D4-1D01-4C51-87E2-6F954A772B59"), exclusiveto, contract] */
                MIDL_INTERFACE("1F6B15D4-1D01-4C51-87E2-6F954A772B59")
                IDisplayMonitor : public IInspectable
                {
                public:
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DeviceId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayName(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_ConnectionKind(
                        /* [retval, out] */__RPC__out ABI::Windows::Devices::Display::DisplayMonitorConnectionKind * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PhysicalConnector(
                        /* [retval, out] */__RPC__out ABI::Windows::Devices::Display::DisplayMonitorPhysicalConnectorKind * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayAdapterDeviceId(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayAdapterId(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::DisplayAdapterId * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_DisplayAdapterTargetId(
                        /* [retval, out] */__RPC__out UINT32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_UsageKind(
                        /* [retval, out] */__RPC__out ABI::Windows::Devices::Display::DisplayMonitorUsageKind * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_NativeResolutionInRawPixels(
                        /* [retval, out] */__RPC__out ABI::Windows::Graphics::SizeInt32 * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_PhysicalSizeInInches(
                        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CSize * * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RawDpiX(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RawDpiY(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_RedPrimary(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Point * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_GreenPrimary(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Point * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_BluePrimary(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Point * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_WhitePoint(
                        /* [retval, out] */__RPC__out ABI::Windows::Foundation::Point * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MaxLuminanceInNits(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MinLuminanceInNits(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    /* [propget] */virtual HRESULT STDMETHODCALLTYPE get_MaxAverageFullFrameLuminanceInNits(
                        /* [retval, out] */__RPC__out FLOAT * value
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE GetDescriptor(
                        /* [in] */ABI::Windows::Devices::Display::DisplayMonitorDescriptorKind descriptorKind,
                        /* [out] */__RPC__out UINT32 * __resultSize,
                        /* [size_is(, *(__resultSize)), retval, out] */__RPC__deref_out_ecount_full_opt(*(__resultSize)) BYTE * * result
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayMonitor=_uuidof(IDisplayMonitor);
                
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor;
#endif /* !defined(____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Display.IDisplayMonitorStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Display.DisplayMonitor
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Display_IDisplayMonitorStatics[] = L"Windows.Devices.Display.IDisplayMonitorStatics";
namespace ABI {
    namespace Windows {
        namespace Devices {
            namespace Display {
                /* [object, uuid("6EAE698F-A228-4C05-821D-B695D667DE8E"), exclusiveto, contract] */
                MIDL_INTERFACE("6EAE698F-A228-4C05-821D-B695D667DE8E")
                IDisplayMonitorStatics : public IInspectable
                {
                public:
                    virtual HRESULT STDMETHODCALLTYPE GetDeviceSelector(
                        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE FromIdAsync(
                        /* [in] */__RPC__in HSTRING deviceId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * * operation
                        ) = 0;
                    virtual HRESULT STDMETHODCALLTYPE FromInterfaceIdAsync(
                        /* [in] */__RPC__in HSTRING deviceInterfaceId,
                        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * * operation
                        ) = 0;
                    
                };

                extern MIDL_CONST_ID IID & IID_IDisplayMonitorStatics=_uuidof(IDisplayMonitorStatics);
                
            } /* Display */
        } /* Devices */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics;
#endif /* !defined(____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Display.DisplayMonitor
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Devices.Display.IDisplayMonitorStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Display.IDisplayMonitor ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Display_DisplayMonitor_DEFINED
#define RUNTIMECLASS_Windows_Devices_Display_DisplayMonitor_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Display_DisplayMonitor[] = L"Windows.Devices.Display.DisplayMonitor";
#endif
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000




#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor;

#endif // ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_FWD_DEFINED__

#ifndef ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_FWD_DEFINED__
#define ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics;

#endif // ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_INTERFACE_DEFINED__)
#define ____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_INTERFACE_DEFINED__

typedef interface __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor;

// Forward declare the async operation.
typedef interface __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor;

typedef struct __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitorVtbl
{
    BEGIN_INTERFACE

    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor * This);

    HRESULT ( STDMETHODCALLTYPE *Invoke )(__RPC__in __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor * This,/* [in] */ __RPC__in_opt __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor *asyncInfo, /* [in] */ AsyncStatus status);
    END_INTERFACE
} __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitorVtbl;

interface __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor
{
    CONST_VTBL struct __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitorVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_Invoke(This,asyncInfo,status)	\
    ( (This)->lpVtbl -> Invoke(This,asyncInfo,status) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_INTERFACE_DEFINED__)
#define ____FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_INTERFACE_DEFINED__

typedef interface __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor;

typedef struct __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitorVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * This);
    ULONG ( STDMETHODCALLTYPE *Release )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * This);

    HRESULT ( STDMETHODCALLTYPE *GetIids )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * This,
        /* [out] */ __RPC__out ULONG *iidCount,
        /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propput] */ HRESULT ( STDMETHODCALLTYPE *put_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * This, /* [in] */ __RPC__in_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor *handler);
    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Completed )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * This, /* [retval][out] */ __RPC__deref_out_opt __FIAsyncOperationCompletedHandler_1_Windows__CDevices__CDisplay__CDisplayMonitor **handler);
    HRESULT ( STDMETHODCALLTYPE *GetResults )(__RPC__in __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * This, /* [retval][out] */ __RPC__out __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * *results);
    END_INTERFACE
} __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitorVtbl;

interface __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor
{
    CONST_VTBL struct __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitorVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_put_Completed(This,handler)	\
    ( (This)->lpVtbl -> put_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_get_Completed(This,handler)	\
    ( (This)->lpVtbl -> get_Completed(This,handler) ) 
#define __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_GetResults(This,results)	\
    ( (This)->lpVtbl -> GetResults(This,results) ) 
#endif /* COBJMACROS */


#endif // ____FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor_INTERFACE_DEFINED__

#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

struct __x_ABI_CWindows_CFoundation_CSize;

#if !defined(____FIReference_1_Windows__CFoundation__CSize_INTERFACE_DEFINED__)
#define ____FIReference_1_Windows__CFoundation__CSize_INTERFACE_DEFINED__

typedef interface __FIReference_1_Windows__CFoundation__CSize __FIReference_1_Windows__CFoundation__CSize;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_Windows__CFoundation__CSize;

typedef struct __FIReference_1_Windows__CFoundation__CSizeVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_Windows__CFoundation__CSize * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_Windows__CFoundation__CSize * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_Windows__CFoundation__CSize * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_Windows__CFoundation__CSize * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_Windows__CFoundation__CSize * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_Windows__CFoundation__CSize * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_Windows__CFoundation__CSize * This, /* [retval][out] */ __RPC__out struct __x_ABI_CWindows_CFoundation_CSize *value);
    END_INTERFACE
} __FIReference_1_Windows__CFoundation__CSizeVtbl;

interface __FIReference_1_Windows__CFoundation__CSize
{
    CONST_VTBL struct __FIReference_1_Windows__CFoundation__CSizeVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_Windows__CFoundation__CSize_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_Windows__CFoundation__CSize_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_Windows__CFoundation__CSize_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_Windows__CFoundation__CSize_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_Windows__CFoundation__CSize_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_Windows__CFoundation__CSize_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_Windows__CFoundation__CSize_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_Windows__CFoundation__CSize_INTERFACE_DEFINED__




typedef struct __x_ABI_CWindows_CFoundation_CPoint __x_ABI_CWindows_CFoundation_CPoint;


typedef struct __x_ABI_CWindows_CFoundation_CSize __x_ABI_CWindows_CFoundation_CSize;





typedef struct __x_ABI_CWindows_CGraphics_CDisplayAdapterId __x_ABI_CWindows_CGraphics_CDisplayAdapterId;


typedef struct __x_ABI_CWindows_CGraphics_CSizeInt32 __x_ABI_CWindows_CGraphics_CSizeInt32;




typedef enum __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorConnectionKind __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorConnectionKind;


typedef enum __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorDescriptorKind __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorDescriptorKind;


typedef enum __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorPhysicalConnectorKind __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorPhysicalConnectorKind;


typedef enum __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorUsageKind __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorUsageKind;












/*
 *
 * Struct Windows.Devices.Display.DisplayMonitorConnectionKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorConnectionKind
{
    DisplayMonitorConnectionKind_Internal = 0,
    DisplayMonitorConnectionKind_Wired = 1,
    DisplayMonitorConnectionKind_Wireless = 2,
    DisplayMonitorConnectionKind_Virtual = 3,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Devices.Display.DisplayMonitorDescriptorKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorDescriptorKind
{
    DisplayMonitorDescriptorKind_Edid = 0,
    DisplayMonitorDescriptorKind_DisplayId = 1,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Devices.Display.DisplayMonitorPhysicalConnectorKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorPhysicalConnectorKind
{
    DisplayMonitorPhysicalConnectorKind_Unknown = 0,
    DisplayMonitorPhysicalConnectorKind_HD15 = 1,
    DisplayMonitorPhysicalConnectorKind_AnalogTV = 2,
    DisplayMonitorPhysicalConnectorKind_Dvi = 3,
    DisplayMonitorPhysicalConnectorKind_Hdmi = 4,
    DisplayMonitorPhysicalConnectorKind_Lvds = 5,
    DisplayMonitorPhysicalConnectorKind_Sdi = 6,
    DisplayMonitorPhysicalConnectorKind_DisplayPort = 7,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Devices.Display.DisplayMonitorUsageKind
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */

#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
/* [v1_enum, contract] */
enum __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorUsageKind
{
    DisplayMonitorUsageKind_Standard = 0,
    DisplayMonitorUsageKind_HeadMounted = 1,
    DisplayMonitorUsageKind_SpecialPurpose = 2,
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Display.IDisplayMonitor
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Display.DisplayMonitor
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Display_IDisplayMonitor[] = L"Windows.Devices.Display.IDisplayMonitor";
/* [object, uuid("1F6B15D4-1D01-4C51-87E2-6F954A772B59"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
/* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DeviceId )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayName )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_ConnectionKind )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorConnectionKind * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PhysicalConnector )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorPhysicalConnectorKind * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayAdapterDeviceId )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayAdapterId )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CDisplayAdapterId * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_DisplayAdapterTargetId )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out UINT32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_UsageKind )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorUsageKind * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_NativeResolutionInRawPixels )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CGraphics_CSizeInt32 * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_PhysicalSizeInInches )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__deref_out_opt __FIReference_1_Windows__CFoundation__CSize * * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RawDpiX )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RawDpiY )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_RedPrimary )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CPoint * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_GreenPrimary )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CPoint * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_BluePrimary )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CPoint * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_WhitePoint )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out __x_ABI_CWindows_CFoundation_CPoint * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MaxLuminanceInNits )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MinLuminanceInNits )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    /* [propget] */HRESULT ( STDMETHODCALLTYPE *get_MaxAverageFullFrameLuminanceInNits )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [retval, out] */__RPC__out FLOAT * value
        );
    HRESULT ( STDMETHODCALLTYPE *GetDescriptor )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor * This,
        /* [in] */__x_ABI_CWindows_CDevices_CDisplay_CDisplayMonitorDescriptorKind descriptorKind,
        /* [out] */__RPC__out UINT32 * __resultSize,
        /* [size_is(, *(__resultSize)), retval, out] */__RPC__deref_out_ecount_full_opt(*(__resultSize)) BYTE * * result
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorVtbl;

interface __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_DeviceId(This,value) \
    ( (This)->lpVtbl->get_DeviceId(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_DisplayName(This,value) \
    ( (This)->lpVtbl->get_DisplayName(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_ConnectionKind(This,value) \
    ( (This)->lpVtbl->get_ConnectionKind(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_PhysicalConnector(This,value) \
    ( (This)->lpVtbl->get_PhysicalConnector(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_DisplayAdapterDeviceId(This,value) \
    ( (This)->lpVtbl->get_DisplayAdapterDeviceId(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_DisplayAdapterId(This,value) \
    ( (This)->lpVtbl->get_DisplayAdapterId(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_DisplayAdapterTargetId(This,value) \
    ( (This)->lpVtbl->get_DisplayAdapterTargetId(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_UsageKind(This,value) \
    ( (This)->lpVtbl->get_UsageKind(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_NativeResolutionInRawPixels(This,value) \
    ( (This)->lpVtbl->get_NativeResolutionInRawPixels(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_PhysicalSizeInInches(This,value) \
    ( (This)->lpVtbl->get_PhysicalSizeInInches(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_RawDpiX(This,value) \
    ( (This)->lpVtbl->get_RawDpiX(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_RawDpiY(This,value) \
    ( (This)->lpVtbl->get_RawDpiY(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_RedPrimary(This,value) \
    ( (This)->lpVtbl->get_RedPrimary(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_GreenPrimary(This,value) \
    ( (This)->lpVtbl->get_GreenPrimary(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_BluePrimary(This,value) \
    ( (This)->lpVtbl->get_BluePrimary(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_WhitePoint(This,value) \
    ( (This)->lpVtbl->get_WhitePoint(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_MaxLuminanceInNits(This,value) \
    ( (This)->lpVtbl->get_MaxLuminanceInNits(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_MinLuminanceInNits(This,value) \
    ( (This)->lpVtbl->get_MinLuminanceInNits(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_get_MaxAverageFullFrameLuminanceInNits(This,value) \
    ( (This)->lpVtbl->get_MaxAverageFullFrameLuminanceInNits(This,value) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_GetDescriptor(This,descriptorKind,__resultSize,result) \
    ( (This)->lpVtbl->GetDescriptor(This,descriptorKind,__resultSize,result) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor;
#endif /* !defined(____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitor_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Interface Windows.Devices.Display.IDisplayMonitorStatics
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * Interface is a part of the implementation of type Windows.Devices.Display.DisplayMonitor
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Devices_Display_IDisplayMonitorStatics[] = L"Windows.Devices.Display.IDisplayMonitorStatics";
/* [object, uuid("6EAE698F-A228-4C05-821D-B695D667DE8E"), exclusiveto, contract] */
typedef struct __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStaticsVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
HRESULT ( STDMETHODCALLTYPE *GetDeviceSelector )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics * This,
        /* [retval, out] */__RPC__deref_out_opt HSTRING * result
        );
    HRESULT ( STDMETHODCALLTYPE *FromIdAsync )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics * This,
        /* [in] */__RPC__in HSTRING deviceId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * * operation
        );
    HRESULT ( STDMETHODCALLTYPE *FromInterfaceIdAsync )(
        __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics * This,
        /* [in] */__RPC__in HSTRING deviceInterfaceId,
        /* [retval, out] */__RPC__deref_out_opt __FIAsyncOperation_1_Windows__CDevices__CDisplay__CDisplayMonitor * * operation
        );
    END_INTERFACE
    
} __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStaticsVtbl;

interface __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics
{
    CONST_VTBL struct __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStaticsVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_GetDeviceSelector(This,result) \
    ( (This)->lpVtbl->GetDeviceSelector(This,result) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_FromIdAsync(This,deviceId,operation) \
    ( (This)->lpVtbl->FromIdAsync(This,deviceId,operation) )

#define __x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_FromInterfaceIdAsync(This,deviceInterfaceId,operation) \
    ( (This)->lpVtbl->FromInterfaceIdAsync(This,deviceInterfaceId,operation) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics;
#endif /* !defined(____x_ABI_CWindows_CDevices_CDisplay_CIDisplayMonitorStatics_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Class Windows.Devices.Display.DisplayMonitor
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 * RuntimeClass contains static methods.
 *   Static Methods exist on the Windows.Devices.Display.IDisplayMonitorStatics interface starting with version 6.0 of the Windows.Foundation.UniversalApiContract API contract
 *
 * Class implements the following interfaces:
 *    Windows.Devices.Display.IDisplayMonitor ** Default Interface **
 *
 * Class Threading Model:  Both Single and Multi Threaded Apartment
 *
 * Class Marshaling Behavior:  Agile - Class is agile
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

#ifndef RUNTIMECLASS_Windows_Devices_Display_DisplayMonitor_DEFINED
#define RUNTIMECLASS_Windows_Devices_Display_DisplayMonitor_DEFINED
extern const __declspec(selectany) _Null_terminated_ WCHAR RuntimeClass_Windows_Devices_Display_DisplayMonitor[] = L"Windows.Devices.Display.DisplayMonitor";
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
#endif // __windows2Edevices2Edisplay_p_h__

#endif // __windows2Edevices2Edisplay_h__
