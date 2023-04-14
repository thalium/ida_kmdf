/*
** This header contains necessary defines and typedefs the absence of which
** would prevent tilib from generating the til files.
**
** Some of those defines and typedefs are from system headers which are not
** included in the wdf headers, or from wdf but without the proper includes
** or a bad order.
**
** Most wdf headers are automatically generated and the order of dependance
** might not be very rigorous.
**
** Besides, tilib allow a base .til to be used, but only one, and no .til
** contains everything necessary.
**
** Some of the definitions here are incomplete (simplified as void * for
** instance), but what counts is their proper definition for tilib to complete
** the .til creation.
*/


#define FORCEINLINE
#define __inline
#define WDFEXPORT(a) imp_ ## a
#define VFWDFEXPORT(a) imp_Vf ## a

typedef unsigned int size_t;

typedef enum {
    DmaComplete,
    DmaAborted,
    DmaError,
    DmaCancelled
} DMA_COMPLETION_STATUS;

typedef struct _GROUP_AFFINITY {
    int Mask;
    USHORT Group;
    USHORT Reserved[3];
} GROUP_AFFINITY, *PGROUP_AFFINITY;


DECLARE_HANDLE( WDFCOMPANIONTARGET );

typedef ULONG_PTR KAFFINITY;
typedef ULONG WDF_MAJOR_VERSION;
typedef ULONG WDF_MINOR_VERSION;
typedef ULONG WDF_BUILD_NUMBER;
typedef PVOID WDF_COMPONENT_GLOBALS, *PWDF_COMPONENT_GLOBALS;
typedef HANDLE POHANDLE;

typedef void* PPO_FX_COMPONENT_IDLE_STATE;
typedef void* PO_FX_COMPONENT_V1;
typedef void* PO_FX_COMPONENT_V2;
typedef void* PPO_FX_COMPONENT_ACTIVE_CONDITION_CALLBACK;
typedef void* PPO_FX_COMPONENT_IDLE_CONDITION_CALLBACK;
typedef void* PPO_FX_COMPONENT_IDLE_STATE_CALLBACK;
typedef void* PPO_FX_COMPONENT;
typedef void* PPO_FX_DEVICE_POWER_NOT_REQUIRED_CALLBACK;
typedef void* PPO_FX_DEVICE_POWER_REQUIRED_CALLBACK;
typedef void* PPO_FX_POWER_CONTROL_CALLBACK;

typedef int (*PWDFCX_FILEOBJECT_CONFIG)(void);
typedef int (*PWDFCX_PNPPOWER_EVENT_CALLBACKS)(void);


typedef int (*PFN_WDFCX_DEVICE_FILE_CREATE)(void);
typedef int (*PFN_WDFDEVICE_WDM_POST_PO_FX_REGISTER_DEVICE)(void);
typedef int (*PFN_WDFDEVICE_WDM_PRE_PO_FX_UNREGISTER_DEVICE)(void);
typedef int (*PFN_WDFCXDEVICE_WDM_IRP_PREPROCESS)(void);
typedef int (*PFN_WDF_CLASS_EXTENSIONIN_BIND)(void);
typedef int (*PFN_WDF_CLASS_EXTENSIONIN_UNBIND)(void);
typedef int (*PFN_WDF_CLASS_EXPORT)(void);
typedef int (*PFN_WDF_CLIENT_BIND_CLASS)(void);
typedef int (*PFN_WDF_CLIENT_UNBIND_CLASS)(void);
typedef int (*PFN_WDF_CLASS_LIBRARY_INITIALIZE)(void);
typedef int (*PFN_WDF_CLASS_LIBRARY_DEINITIALIZE)(void);
typedef int (*PFN_WDF_CLASS_LIBRARY_BIND_CLIENT)(void);
typedef int (*PFN_WDF_CLASS_LIBRARY_UNBIND_CLIENT)(void);
