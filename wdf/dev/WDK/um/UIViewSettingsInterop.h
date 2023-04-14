

/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0622 */
/* @@MIDL_FILE_HEADING(  ) */



/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 500
#endif

/* verify that the <rpcsal.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCSAL_H_VERSION__
#define __REQUIRED_RPCSAL_H_VERSION__ 100
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */

#ifndef COM_NO_WINDOWS_H
#include "windows.h"
#include "ole2.h"
#endif /*COM_NO_WINDOWS_H*/

#ifndef __uiviewsettingsinterop_h__
#define __uiviewsettingsinterop_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef __IUIViewSettingsInterop_FWD_DEFINED__
#define __IUIViewSettingsInterop_FWD_DEFINED__
typedef interface IUIViewSettingsInterop IUIViewSettingsInterop;

#endif 	/* __IUIViewSettingsInterop_FWD_DEFINED__ */


#ifndef __IClassicApplicationViewFactory_FWD_DEFINED__
#define __IClassicApplicationViewFactory_FWD_DEFINED__
typedef interface IClassicApplicationViewFactory IClassicApplicationViewFactory;

#endif 	/* __IClassicApplicationViewFactory_FWD_DEFINED__ */


#ifndef __IClassicApplicationView_FWD_DEFINED__
#define __IClassicApplicationView_FWD_DEFINED__
typedef interface IClassicApplicationView IClassicApplicationView;

#endif 	/* __IClassicApplicationView_FWD_DEFINED__ */


#ifndef __ClassicApplicationViewFactory_FWD_DEFINED__
#define __ClassicApplicationViewFactory_FWD_DEFINED__

#ifdef __cplusplus
typedef class ClassicApplicationViewFactory ClassicApplicationViewFactory;
#else
typedef struct ClassicApplicationViewFactory ClassicApplicationViewFactory;
#endif /* __cplusplus */

#endif 	/* __ClassicApplicationViewFactory_FWD_DEFINED__ */


/* header files for imported files */
#include "inspectable.h"

#ifdef __cplusplus
extern "C"{
#endif 


/* interface __MIDL_itf_uiviewsettingsinterop_0000_0000 */
/* [local] */ 

#include <winapifamily.h>
#if (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#pragma region Desktop Family
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)


extern RPC_IF_HANDLE __MIDL_itf_uiviewsettingsinterop_0000_0000_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_uiviewsettingsinterop_0000_0000_v0_0_s_ifspec;

#ifndef __IUIViewSettingsInterop_INTERFACE_DEFINED__
#define __IUIViewSettingsInterop_INTERFACE_DEFINED__

/* interface IUIViewSettingsInterop */
/* [object][uuid] */ 


EXTERN_C const IID IID_IUIViewSettingsInterop;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("3694dbf9-8f68-44be-8ff5-195c98ede8a6")
    IUIViewSettingsInterop : public IInspectable
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE GetForWindow( 
            /* [in] */ __RPC__in HWND hwnd,
            /* [in] */ __RPC__in REFIID riid,
            /* [iid_is][retval][out] */ __RPC__deref_out_opt void **ppv) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IUIViewSettingsInteropVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            __RPC__in IUIViewSettingsInterop * This,
            /* [in] */ __RPC__in REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            __RPC__in IUIViewSettingsInterop * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            __RPC__in IUIViewSettingsInterop * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetIids )( 
            __RPC__in IUIViewSettingsInterop * This,
            /* [out] */ __RPC__out ULONG *iidCount,
            /* [size_is][size_is][out] */ __RPC__deref_out_ecount_full_opt(*iidCount) IID **iids);
        
        HRESULT ( STDMETHODCALLTYPE *GetRuntimeClassName )( 
            __RPC__in IUIViewSettingsInterop * This,
            /* [out] */ __RPC__deref_out_opt HSTRING *className);
        
        HRESULT ( STDMETHODCALLTYPE *GetTrustLevel )( 
            __RPC__in IUIViewSettingsInterop * This,
            /* [out] */ __RPC__out TrustLevel *trustLevel);
        
        HRESULT ( STDMETHODCALLTYPE *GetForWindow )( 
            __RPC__in IUIViewSettingsInterop * This,
            /* [in] */ __RPC__in HWND hwnd,
            /* [in] */ __RPC__in REFIID riid,
            /* [iid_is][retval][out] */ __RPC__deref_out_opt void **ppv);
        
        END_INTERFACE
    } IUIViewSettingsInteropVtbl;

    interface IUIViewSettingsInterop
    {
        CONST_VTBL struct IUIViewSettingsInteropVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IUIViewSettingsInterop_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IUIViewSettingsInterop_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IUIViewSettingsInterop_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IUIViewSettingsInterop_GetIids(This,iidCount,iids)	\
    ( (This)->lpVtbl -> GetIids(This,iidCount,iids) ) 

#define IUIViewSettingsInterop_GetRuntimeClassName(This,className)	\
    ( (This)->lpVtbl -> GetRuntimeClassName(This,className) ) 

#define IUIViewSettingsInterop_GetTrustLevel(This,trustLevel)	\
    ( (This)->lpVtbl -> GetTrustLevel(This,trustLevel) ) 


#define IUIViewSettingsInterop_GetForWindow(This,hwnd,riid,ppv)	\
    ( (This)->lpVtbl -> GetForWindow(This,hwnd,riid,ppv) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IUIViewSettingsInterop_INTERFACE_DEFINED__ */


/* interface __MIDL_itf_uiviewsettingsinterop_0000_0001 */
/* [local] */ 

#endif /* WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP) */
#pragma endregion
#endif //(NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
#if (NTDDI_VERSION >= NTDDI_WIN10_RS5)
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)


extern RPC_IF_HANDLE __MIDL_itf_uiviewsettingsinterop_0000_0001_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_uiviewsettingsinterop_0000_0001_v0_0_s_ifspec;

#ifndef __IClassicApplicationViewFactory_INTERFACE_DEFINED__
#define __IClassicApplicationViewFactory_INTERFACE_DEFINED__

/* interface IClassicApplicationViewFactory */
/* [object][local][uuid] */ 


EXTERN_C const IID IID_IClassicApplicationViewFactory;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("ECC62F5D-14AA-4971-9F06-B2159B1FFD40")
    IClassicApplicationViewFactory : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE GetForWindow( 
            /* [in] */ HWND appWindow,
            /* [in] */ REFIID riid,
            /* [iid_is][retval][out] */ void **result) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IClassicApplicationViewFactoryVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IClassicApplicationViewFactory * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IClassicApplicationViewFactory * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IClassicApplicationViewFactory * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetForWindow )( 
            IClassicApplicationViewFactory * This,
            /* [in] */ HWND appWindow,
            /* [in] */ REFIID riid,
            /* [iid_is][retval][out] */ void **result);
        
        END_INTERFACE
    } IClassicApplicationViewFactoryVtbl;

    interface IClassicApplicationViewFactory
    {
        CONST_VTBL struct IClassicApplicationViewFactoryVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IClassicApplicationViewFactory_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IClassicApplicationViewFactory_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IClassicApplicationViewFactory_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IClassicApplicationViewFactory_GetForWindow(This,appWindow,riid,result)	\
    ( (This)->lpVtbl -> GetForWindow(This,appWindow,riid,result) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IClassicApplicationViewFactory_INTERFACE_DEFINED__ */


#ifndef __IClassicApplicationView_INTERFACE_DEFINED__
#define __IClassicApplicationView_INTERFACE_DEFINED__

/* interface IClassicApplicationView */
/* [object][local][uuid] */ 


EXTERN_C const IID IID_IClassicApplicationView;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("7A05F995-6242-440E-A64E-34B7ED3413D3")
    IClassicApplicationView : public IUnknown
    {
    public:
        virtual HRESULT STDMETHODCALLTYPE GetTitleBar( 
            /* [in] */ REFIID riid,
            /* [iid_is][retval][out] */ void **result) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE GetActiveIcon( 
            /* [retval][out] */ HICON *value) = 0;
        
        virtual HRESULT STDMETHODCALLTYPE SetActiveIcon( 
            /* [in] */ HICON value) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IClassicApplicationViewVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IClassicApplicationView * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IClassicApplicationView * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IClassicApplicationView * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTitleBar )( 
            IClassicApplicationView * This,
            /* [in] */ REFIID riid,
            /* [iid_is][retval][out] */ void **result);
        
        HRESULT ( STDMETHODCALLTYPE *GetActiveIcon )( 
            IClassicApplicationView * This,
            /* [retval][out] */ HICON *value);
        
        HRESULT ( STDMETHODCALLTYPE *SetActiveIcon )( 
            IClassicApplicationView * This,
            /* [in] */ HICON value);
        
        END_INTERFACE
    } IClassicApplicationViewVtbl;

    interface IClassicApplicationView
    {
        CONST_VTBL struct IClassicApplicationViewVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IClassicApplicationView_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IClassicApplicationView_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IClassicApplicationView_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IClassicApplicationView_GetTitleBar(This,riid,result)	\
    ( (This)->lpVtbl -> GetTitleBar(This,riid,result) ) 

#define IClassicApplicationView_GetActiveIcon(This,value)	\
    ( (This)->lpVtbl -> GetActiveIcon(This,value) ) 

#define IClassicApplicationView_SetActiveIcon(This,value)	\
    ( (This)->lpVtbl -> SetActiveIcon(This,value) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IClassicApplicationView_INTERFACE_DEFINED__ */



#ifndef __UIViewSettingsInterop_LIBRARY_DEFINED__
#define __UIViewSettingsInterop_LIBRARY_DEFINED__

/* library UIViewSettingsInterop */
/* [uuid] */ 


EXTERN_C const IID LIBID_UIViewSettingsInterop;

EXTERN_C const CLSID CLSID_ClassicApplicationViewFactory;

#ifdef __cplusplus

class DECLSPEC_UUID("4A765F48-1D55-49DE-9B20-19F09AD0D1A7")
ClassicApplicationViewFactory;
#endif
#endif /* __UIViewSettingsInterop_LIBRARY_DEFINED__ */

/* interface __MIDL_itf_uiviewsettingsinterop_0000_0004 */
/* [local] */ 

#ifdef __cplusplus
constexpr PCWSTR TitleBarBackgroundColor     = L"TitleBar.BackgroundColor";
constexpr PCWSTR TitleBarForegroundColor     = L"TitleBar.ForegroundColor";
constexpr PCWSTR TitleBarIcon                = L"TitleBar.Icon";
#endif
#endif /* WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP) */
#endif // (NTDDI_VERSION >= NTDDI_WIN10_RS5)


extern RPC_IF_HANDLE __MIDL_itf_uiviewsettingsinterop_0000_0004_v0_0_c_ifspec;
extern RPC_IF_HANDLE __MIDL_itf_uiviewsettingsinterop_0000_0004_v0_0_s_ifspec;

/* Additional Prototypes for ALL interfaces */

unsigned long             __RPC_USER  HWND_UserSize(     __RPC__in unsigned long *, unsigned long            , __RPC__in HWND * ); 
unsigned char * __RPC_USER  HWND_UserMarshal(  __RPC__in unsigned long *, __RPC__inout_xcount(0) unsigned char *, __RPC__in HWND * ); 
unsigned char * __RPC_USER  HWND_UserUnmarshal(__RPC__in unsigned long *, __RPC__in_xcount(0) unsigned char *, __RPC__out HWND * ); 
void                      __RPC_USER  HWND_UserFree(     __RPC__in unsigned long *, __RPC__in HWND * ); 

unsigned long             __RPC_USER  HWND_UserSize64(     __RPC__in unsigned long *, unsigned long            , __RPC__in HWND * ); 
unsigned char * __RPC_USER  HWND_UserMarshal64(  __RPC__in unsigned long *, __RPC__inout_xcount(0) unsigned char *, __RPC__in HWND * ); 
unsigned char * __RPC_USER  HWND_UserUnmarshal64(__RPC__in unsigned long *, __RPC__in_xcount(0) unsigned char *, __RPC__out HWND * ); 
void                      __RPC_USER  HWND_UserFree64(     __RPC__in unsigned long *, __RPC__in HWND * ); 

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif


