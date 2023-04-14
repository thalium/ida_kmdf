/* Header file automatically generated from windows.graphics.idl */
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
#ifndef __windows2Egraphics_h__
#define __windows2Egraphics_h__
#ifndef __windows2Egraphics_p_h__
#define __windows2Egraphics_p_h__


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
#ifndef ____x_ABI_CWindows_CGraphics_CIGeometrySource2D_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CIGeometrySource2D_FWD_DEFINED__
namespace ABI {
    namespace Windows {
        namespace Graphics {
            interface IGeometrySource2D;
        } /* Graphics */
    } /* Windows */} /* ABI */
#define __x_ABI_CWindows_CGraphics_CIGeometrySource2D ABI::Windows::Graphics::IGeometrySource2D

#endif // ____x_ABI_CWindows_CGraphics_CIGeometrySource2D_FWD_DEFINED__

// Parameterized interface forward declarations (C++)

// Collection interface definitions
namespace ABI {
    namespace Windows {
        namespace Graphics {
            struct SizeInt32;
            
        } /* Graphics */
    } /* Windows */} /* ABI */


#ifndef DEF___FIReference_1_Windows__CGraphics__CSizeInt32_USE
#define DEF___FIReference_1_Windows__CGraphics__CSizeInt32_USE
#if !defined(RO_NO_TEMPLATE_NAME)
namespace ABI { namespace Windows { namespace Foundation {
template <>
struct __declspec(uuid("b77aa86d-2d6e-55f1-8f99-64ac5c05328b"))
IReference<struct ABI::Windows::Graphics::SizeInt32> : IReference_impl<struct ABI::Windows::Graphics::SizeInt32> 
{
    static const wchar_t* z_get_rc_name_impl() 
    {
        return L"Windows.Foundation.IReference`1<Windows.Graphics.SizeInt32>"; 
    }
};
// Define a typedef for the parameterized interface specialization's mangled name.
// This allows code which uses the mangled name for the parameterized interface to access the
// correct parameterized interface specialization.
typedef IReference<struct ABI::Windows::Graphics::SizeInt32> __FIReference_1_Windows__CGraphics__CSizeInt32_t;
#define __FIReference_1_Windows__CGraphics__CSizeInt32 ABI::Windows::Foundation::__FIReference_1_Windows__CGraphics__CSizeInt32_t
/* Foundation */ } /* Windows */ } /* ABI */ } 

////  Define an alias for the C version of the interface for compatibility purposes.
//#define __FIReference_1_Windows__CGraphics__CSizeInt32 ABI::Windows::Foundation::IReference<ABI::Windows::Graphics::SizeInt32>
//#define __FIReference_1_Windows__CGraphics__CSizeInt32_t ABI::Windows::Foundation::IReference<ABI::Windows::Graphics::SizeInt32>
#endif // !defined(RO_NO_TEMPLATE_NAME)
#endif /* DEF___FIReference_1_Windows__CGraphics__CSizeInt32_USE */








namespace ABI {
    namespace Windows {
        namespace Graphics {
            
            typedef struct DisplayAdapterId DisplayAdapterId;
            
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            
            typedef struct PointInt32 PointInt32;
            
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            
            typedef struct RectInt32 RectInt32;
            
        } /* Graphics */
    } /* Windows */} /* ABI */

namespace ABI {
    namespace Windows {
        namespace Graphics {
            
            typedef struct SizeInt32 SizeInt32;
            
        } /* Graphics */
    } /* Windows */} /* ABI */








/*
 *
 * Struct Windows.Graphics.DisplayAdapterId
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

namespace ABI {
    namespace Windows {
        namespace Graphics {
            /* [contract] */
            struct DisplayAdapterId
            {
                UINT32 LowPart;
                INT32 HighPart;
            };
            
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Graphics.PointInt32
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

namespace ABI {
    namespace Windows {
        namespace Graphics {
            /* [contract] */
            struct PointInt32
            {
                INT32 X;
                INT32 Y;
            };
            
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Struct Windows.Graphics.RectInt32
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

namespace ABI {
    namespace Windows {
        namespace Graphics {
            /* [contract] */
            struct RectInt32
            {
                INT32 X;
                INT32 Y;
                INT32 Width;
                INT32 Height;
            };
            
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Struct Windows.Graphics.SizeInt32
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

namespace ABI {
    namespace Windows {
        namespace Graphics {
            /* [contract] */
            struct SizeInt32
            {
                INT32 Width;
                INT32 Height;
            };
            
        } /* Graphics */
    } /* Windows */} /* ABI */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Graphics.IGeometrySource2D
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CIGeometrySource2D_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CIGeometrySource2D_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_IGeometrySource2D[] = L"Windows.Graphics.IGeometrySource2D";
namespace ABI {
    namespace Windows {
        namespace Graphics {
            /* [object, uuid("CAFF7902-670C-4181-A624-DA977203B845"), contract] */
            MIDL_INTERFACE("CAFF7902-670C-4181-A624-DA977203B845")
            IGeometrySource2D : public IInspectable
            {
            public:
                
            };

            extern MIDL_CONST_ID IID & IID_IGeometrySource2D=_uuidof(IGeometrySource2D);
            
        } /* Graphics */
    } /* Windows */} /* ABI */

EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CIGeometrySource2D;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CIGeometrySource2D_INTERFACE_DEFINED__) */
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000



#else // !defined(__cplusplus)
/* Forward Declarations */
#ifndef ____x_ABI_CWindows_CGraphics_CIGeometrySource2D_FWD_DEFINED__
#define ____x_ABI_CWindows_CGraphics_CIGeometrySource2D_FWD_DEFINED__
typedef interface __x_ABI_CWindows_CGraphics_CIGeometrySource2D __x_ABI_CWindows_CGraphics_CIGeometrySource2D;

#endif // ____x_ABI_CWindows_CGraphics_CIGeometrySource2D_FWD_DEFINED__

// Parameterized interface forward declarations (C)

// Collection interface definitions
struct __x_ABI_CWindows_CGraphics_CSizeInt32;

#if !defined(____FIReference_1_Windows__CGraphics__CSizeInt32_INTERFACE_DEFINED__)
#define ____FIReference_1_Windows__CGraphics__CSizeInt32_INTERFACE_DEFINED__

typedef interface __FIReference_1_Windows__CGraphics__CSizeInt32 __FIReference_1_Windows__CGraphics__CSizeInt32;

//  Declare the parameterized interface IID.
EXTERN_C const IID IID___FIReference_1_Windows__CGraphics__CSizeInt32;

typedef struct __FIReference_1_Windows__CGraphics__CSizeInt32Vtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface )(__RPC__in __FIReference_1_Windows__CGraphics__CSizeInt32 * This,
        /* [in] */ __RPC__in REFIID riid,
        /* [annotation][iid_is][out] */ 
        _COM_Outptr_  void **ppvObject);
    ULONG ( STDMETHODCALLTYPE *AddRef )( __RPC__in __FIReference_1_Windows__CGraphics__CSizeInt32 * This );
    ULONG ( STDMETHODCALLTYPE *Release )( __RPC__in __FIReference_1_Windows__CGraphics__CSizeInt32 * This );

    HRESULT ( STDMETHODCALLTYPE *GetIids )( __RPC__in __FIReference_1_Windows__CGraphics__CSizeInt32 * This, 
                                            /* [out] */ __RPC__out ULONG *iidCount,
                                            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
    HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( __RPC__in __FIReference_1_Windows__CGraphics__CSizeInt32 * This, /* [out] */ __RPC__deref_out_opt HSTRING *className);
    HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( __RPC__in __FIReference_1_Windows__CGraphics__CSizeInt32 * This, /* [out] */ __RPC__out TrustLevel *trustLevel);

    /* [propget] */ HRESULT ( STDMETHODCALLTYPE *get_Value )(__RPC__in __FIReference_1_Windows__CGraphics__CSizeInt32 * This, /* [retval][out] */ __RPC__out struct __x_ABI_CWindows_CGraphics_CSizeInt32 *value);
    END_INTERFACE
} __FIReference_1_Windows__CGraphics__CSizeInt32Vtbl;

interface __FIReference_1_Windows__CGraphics__CSizeInt32
{
    CONST_VTBL struct __FIReference_1_Windows__CGraphics__CSizeInt32Vtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __FIReference_1_Windows__CGraphics__CSizeInt32_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 
#define __FIReference_1_Windows__CGraphics__CSizeInt32_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 
#define __FIReference_1_Windows__CGraphics__CSizeInt32_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 

#define __FIReference_1_Windows__CGraphics__CSizeInt32_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 
#define __FIReference_1_Windows__CGraphics__CSizeInt32_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 
#define __FIReference_1_Windows__CGraphics__CSizeInt32_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 

#define __FIReference_1_Windows__CGraphics__CSizeInt32_get_Value(This,value)	\
    ( (This)->lpVtbl -> get_Value(This,value) ) 
#endif /* COBJMACROS */


#endif // ____FIReference_1_Windows__CGraphics__CSizeInt32_INTERFACE_DEFINED__







typedef struct __x_ABI_CWindows_CGraphics_CDisplayAdapterId __x_ABI_CWindows_CGraphics_CDisplayAdapterId;


typedef struct __x_ABI_CWindows_CGraphics_CPointInt32 __x_ABI_CWindows_CGraphics_CPointInt32;


typedef struct __x_ABI_CWindows_CGraphics_CRectInt32 __x_ABI_CWindows_CGraphics_CRectInt32;


typedef struct __x_ABI_CWindows_CGraphics_CSizeInt32 __x_ABI_CWindows_CGraphics_CSizeInt32;








/*
 *
 * Struct Windows.Graphics.DisplayAdapterId
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000

/* [contract] */
struct __x_ABI_CWindows_CGraphics_CDisplayAdapterId
{
    UINT32 LowPart;
    INT32 HighPart;
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000


/*
 *
 * Struct Windows.Graphics.PointInt32
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

/* [contract] */
struct __x_ABI_CWindows_CGraphics_CPointInt32
{
    INT32 X;
    INT32 Y;
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Struct Windows.Graphics.RectInt32
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

/* [contract] */
struct __x_ABI_CWindows_CGraphics_CRectInt32
{
    INT32 X;
    INT32 Y;
    INT32 Width;
    INT32 Height;
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Struct Windows.Graphics.SizeInt32
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 4.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000

/* [contract] */
struct __x_ABI_CWindows_CGraphics_CSizeInt32
{
    INT32 Width;
    INT32 Height;
};
#endif // WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x40000


/*
 *
 * Interface Windows.Graphics.IGeometrySource2D
 *
 * Introduced to Windows.Foundation.UniversalApiContract in version 6.0
 *
 *
 */
#if WINDOWS_FOUNDATION_UNIVERSALAPICONTRACT_VERSION >= 0x60000
#if !defined(____x_ABI_CWindows_CGraphics_CIGeometrySource2D_INTERFACE_DEFINED__)
#define ____x_ABI_CWindows_CGraphics_CIGeometrySource2D_INTERFACE_DEFINED__
extern const __declspec(selectany) _Null_terminated_ WCHAR InterfaceName_Windows_Graphics_IGeometrySource2D[] = L"Windows.Graphics.IGeometrySource2D";
/* [object, uuid("CAFF7902-670C-4181-A624-DA977203B845"), contract] */
typedef struct __x_ABI_CWindows_CGraphics_CIGeometrySource2DVtbl
{
    BEGIN_INTERFACE
    HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
    __RPC__in __x_ABI_CWindows_CGraphics_CIGeometrySource2D * This,
    /* [in] */ __RPC__in REFIID riid,
    /* [annotation][iid_is][out] */
    _COM_Outptr_  void **ppvObject
    );

ULONG ( STDMETHODCALLTYPE *AddRef )(
    __RPC__in __x_ABI_CWindows_CGraphics_CIGeometrySource2D * This
    );

ULONG ( STDMETHODCALLTYPE *Release )(
    __RPC__in __x_ABI_CWindows_CGraphics_CIGeometrySource2D * This
    );

HRESULT ( STDMETHODCALLTYPE *GetIids )(
    __RPC__in __x_ABI_CWindows_CGraphics_CIGeometrySource2D * This,
    /* [out] */ __RPC__out ULONG *iidCount,
    /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids
    );

HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )(
    __RPC__in __x_ABI_CWindows_CGraphics_CIGeometrySource2D * This,
    /* [out] */ __RPC__deref_out_opt HSTRING *className
    );

HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )(
    __RPC__in __x_ABI_CWindows_CGraphics_CIGeometrySource2D * This,
    /* [OUT ] */ __RPC__out TrustLevel *trustLevel
    );
END_INTERFACE
    
} __x_ABI_CWindows_CGraphics_CIGeometrySource2DVtbl;

interface __x_ABI_CWindows_CGraphics_CIGeometrySource2D
{
    CONST_VTBL struct __x_ABI_CWindows_CGraphics_CIGeometrySource2DVtbl *lpVtbl;
};

#ifdef COBJMACROS
#define __x_ABI_CWindows_CGraphics_CIGeometrySource2D_QueryInterface(This,riid,ppvObject) \
( (This)->lpVtbl->QueryInterface(This,riid,ppvObject) )

#define __x_ABI_CWindows_CGraphics_CIGeometrySource2D_AddRef(This) \
        ( (This)->lpVtbl->AddRef(This) )

#define __x_ABI_CWindows_CGraphics_CIGeometrySource2D_Release(This) \
        ( (This)->lpVtbl->Release(This) )

#define __x_ABI_CWindows_CGraphics_CIGeometrySource2D_GetIids(This,iidCount,iids) \
        ( (This)->lpVtbl->GetIids(This,iidCount,iids) )

#define __x_ABI_CWindows_CGraphics_CIGeometrySource2D_GetRuntimeClassName(This,className) \
        ( (This)->lpVtbl->GetRuntimeClassName(This,className) )

#define __x_ABI_CWindows_CGraphics_CIGeometrySource2D_GetTrustLevel(This,trustLevel) \
        ( (This)->lpVtbl->GetTrustLevel(This,trustLevel) )


#endif /* COBJMACROS */


EXTERN_C const IID IID___x_ABI_CWindows_CGraphics_CIGeometrySource2D;
#endif /* !defined(____x_ABI_CWindows_CGraphics_CIGeometrySource2D_INTERFACE_DEFINED__) */
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
#endif // __windows2Egraphics_p_h__

#endif // __windows2Egraphics_h__
