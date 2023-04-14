/*-------------------------------------------------------------------------------------
 *
 * Copyright (c) Microsoft Corporation
 *
 *-------------------------------------------------------------------------------------*/

#ifdef _MSC_VER
#pragma once
#endif //_MSC_VER

#if NTDDI_VERSION >= NTDDI_WIN10_19H1
#if WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP | WINAPI_PARTITION_GAMES)

EXTERN_C
HRESULT
WINAPI
PerceptionDeviceCreateFactory(
    _In_ REFIID riid,
    _Outptr_ LPVOID* ppFactory);

#include <PerceptionDeviceCore.h>
#include <unknwn.h>

enum class PerceptionDeviceOptions
{
    None = 0x0, // Async + Unprivileged

    //! Open the device for privileged access (in read+write mode)
    Privileged = 0x1,
};
DEFINE_ENUM_FLAG_OPERATORS( PerceptionDeviceOptions );

// Forward Declarations
struct IPerceptionDevice;
struct IPerceptionDeviceObjectSubscription;
struct IPerceptionDeviceStateStream;
struct IPerceptionDeviceStateStreamReader;
struct IPerceptionDevicePropertyListener;
struct IPerceptionDeviceRootObjectWatcher;

MIDL_INTERFACE("{81A9D645-1D04-4778-8AF0-83FA08A9D9B7}")
IPerceptionDevicePropertyChangedEventArgs : public IUnknown
{
    STDMETHOD_(UINT, GetValueSize)() = 0;
    STDMETHOD_(const void*, GetValue)() = 0;
    STDMETHOD_(const LUID&, GetChangeId)() = 0;
};

MIDL_INTERFACE("{93D35D5F-B33F-42F3-9795-3973C6D919AE}")
IPerceptionDevicePropertyChangedHandler : public IUnknown
{
    STDMETHOD(Invoke)(
        _In_ IPerceptionDevicePropertyListener* sender,
        _In_ IPerceptionDevicePropertyChangedEventArgs* eventArgs) = 0;
};

MIDL_INTERFACE("{0E2FAE1E-C75C-4530-91B9-8F264540F8CC}")
IPerceptionDevicePropertyListener : public IUnknown
{
    //! Sets the property changed handler.
    //! The callback must be set before calling Start()
    STDMETHOD(SetPropertyChangedHandler)(
        _In_ IPerceptionDevicePropertyChangedHandler* handler) = 0;

    //! Start listening for property changes.
    //! The callback will be invoked with the initial value of the property as soon as possible
    //! after Start() is called.
    //! Note that the callback may be invoked even before Start() returns.
    STDMETHOD(Start)() = 0;

    //! Stop listening for property changes.
    //! Callbacks will not be invoked after Stop returns.
    STDMETHOD(Stop)() = 0;

    //! Returns the device used to create this listener, and thus won't fail.
    STDMETHOD_(__success(true) void, GetDevice)(
        _COM_Outptr_ IPerceptionDevice** device) = 0;

    //! Returns the id of the object that the watched property belongs to.
    //! Returned reference is only valid as long as a strong reference is held to the listener.
    STDMETHOD_(REFGUID, GetObjectId)() = 0;

    //! Returns the property guid being watched on the object
    //! Returned reference is only valid as long as a strong reference is held to the listener.
    STDMETHOD_(REFGUID, GetPropertyId)() = 0;
};

MIDL_INTERFACE("{C8F21EB1-9411-4516-A8A1-B778CF767287}")
IPerceptionDevice : public IUnknown
{
    //! Get a property of known size, into caller-allocated memory.
    //! Returns HRESULT_FROM_WIN32(ERROR_INVALID_DATA) if driver doesn't return the expected amount of data.
    STDMETHOD(ReadProperty)(
        REFGUID objectId,
        REFGUID propertyId,
        UINT valueSize,
        _Out_writes_bytes_all_(valueSize) void* value,
        _Out_opt_ LUID* changeId) = 0;

    //! Get a property of variable size.
    //! The returned buffer is is CoTaskMemAlloc'd, and the caller must free it with CoTaskMemFree.
    STDMETHOD(ReadVariableSizeProperty)(
        REFGUID objectId,
        REFGUID propertyId,
        _Out_ UINT* valueSize,
        _Outptr_result_bytebuffer_all_maybenull_(*valueSize) void** value,
        _Out_opt_ LUID* changeId) = 0;

    //! Create an instance of IPropertyListener that listens for changes to the specified
    //! property on the specified object.
    //! objectId may be GUID_NULL to listen to a top-level property on the device.
    //! This method will fail if the property is not supported.
    //! This method will fail if the device returns a failure when querying the property.
    //! Will invoke the callback with initial value as soon as possible after creation.
    STDMETHOD(CreatePropertyListener)(
        REFGUID objectId,
        REFGUID propertyId,
        _COM_Outptr_ IPerceptionDevicePropertyListener** listener) = 0;

    //! Synchronously send a custom command to the object, with a known / fixed-size output,
    //!
    //! Returns HRESULT_FROM_WIN32(ERROR_INVALID_DATA) if the driver doesn't return the expected amount of data.
    //! The inBuffer may be nullptr if inBufferSize is zero, and the command does not require input.
    //! outBufferSize and outBuffer may be 0 and nullptr if the command does not generate output.
    STDMETHOD(SendCommand)(
        REFGUID objectId,
        REFGUID commandId,
        UINT inBufferSize,
        _In_reads_bytes_opt_(inBufferSize) const void* inBuffer,
        UINT outBufferSize,
        _Out_writes_bytes_all_opt_(outBufferSize) void* outBuffer) = 0;

    //! Synchronously send a custom command to the object.
    //! The inBuffer may be nullptr if inBufferSize is zero, and the command does not require input.
    //! outBufferSize and outBuffer may be nullptr if the command does not generate output.
    //! Resulting memory is CoTaskMemAlloc'd. The caller must free the buffer with CoTaskMemFree.
    STDMETHOD(SendCommandWithVariableSizeOutput)(
        REFGUID objectId,
        REFGUID commandId,
        UINT inBufferSize,
        _In_reads_bytes_opt_(inBufferSize) const void* inBuffer,
        _Out_opt_ UINT* outBufferSize,
        _Outptr_opt_result_bytebuffer_all_maybenull_(*outBufferSize) void** outBuffer) = 0;

    //! Returns the device interface path for this device.
    //! The returned pointer is only valid while the caller holds a reference to this device object.
    STDMETHOD_(_Ret_z_ LPCWSTR, GetDeviceInterfacePath)() = 0;

    //! Returns the options with which the device was opened.
    STDMETHOD_(PerceptionDeviceOptions, GetOptions)() = 0;

    //! Returns the device lifetime id for this device.
    //! All IPerceptionDevice instances that are communicating with the same device and driver session
    //! will have the same LifetimeId.  
    //! This can be used to disambiguate unplug / replug / driver crash situations.
    STDMETHOD_(REFGUID, GetLifetimeId)() = 0;

    //! Create an IPerceptionDeviceStateStream from this device for the specified state stream object id.
    STDMETHOD(CreateStateStream)(
        REFGUID stateStreamObjectId,
        _COM_Outptr_ IPerceptionDeviceStateStream** stateStream) = 0;

    //! Create an object that holds a subscription to the specified spatial object
    //! Can NOT be used on state streams.
    STDMETHOD(CreateObjectSubscription)(
        REFGUID objectId,
        UINT subscriptionFlags,
        _COM_Outptr_ IPerceptionDeviceObjectSubscription** subscription) = 0;
};

MIDL_INTERFACE("{B6B43FBF-92D3-4467-8FFF-553EA84ED9BA}")
IPerceptionDeviceRootObjectAddedEventArgs : public IUnknown
{
    STDMETHOD_(__success(true) void, GetDevice)(_COM_Outptr_ IPerceptionDevice** device) = 0;
    STDMETHOD_(REFGUID, GetPropertyId)() = 0;
    STDMETHOD_(REFGUID, GetObjectId)() = 0;
};

MIDL_INTERFACE("{0E69DBE3-CBA4-4677-98F8-E26EFC983632}")
IPerceptionDeviceRootObjectAddedHandler : public IUnknown
{
    STDMETHOD(Invoke)(
        _In_ IPerceptionDeviceRootObjectWatcher* sender,
        _In_ IPerceptionDeviceRootObjectAddedEventArgs* args) = 0;
};

MIDL_INTERFACE("{CB9C24BC-2778-4A5C-B7EF-91D34025BF6A}")
IPerceptionDeviceRootObjectRemovedEventArgs : public IUnknown
{
    STDMETHOD_(__success(true) void, GetDevice)(_COM_Outptr_ IPerceptionDevice** device) = 0;
    STDMETHOD_(REFGUID, GetPropertyId)() = 0;
    STDMETHOD_(REFGUID, GetObjectId)() = 0;
};

MIDL_INTERFACE("{F720BF56-3D90-4421-B1EF-4F8F5EDC7A07}")
IPerceptionDeviceRootObjectRemovedHandler : public IUnknown
{
    STDMETHOD(Invoke)(
        _In_ IPerceptionDeviceRootObjectWatcher* sender,
        _In_ IPerceptionDeviceRootObjectRemovedEventArgs* args) = 0;
};

MIDL_INTERFACE("{2F22B1BD-7431-4452-92D6-D31557570F33}")
IPerceptionDeviceRootObjectWatcher : public IUnknown
{
    //! Sets the added callback.
    //! The callback must be set before calling Start().
    STDMETHOD(SetAddedHandler)(
        _In_ IPerceptionDeviceRootObjectAddedHandler* handler) = 0;

    //! Sets the removed callback.
    //! The callback must be set before calling Start().
    STDMETHOD(SetRemovedHandler)(
        _In_ IPerceptionDeviceRootObjectRemovedHandler* handler) = 0;

    //! Start listening for property changes.
    //! Callbacks can actually start occurring even before Start() returns.
    STDMETHOD(Start)() = 0;

    //! Stop listening for property changes.
    //! Callbacks will not be raised after Stop returns.
    STDMETHOD(Stop)() = 0;
};

MIDL_INTERFACE("{5FB106F4-A5C7-43C8-A723-232B4456DC6C}")
IPerceptionDevicePayloadDescriptor : public IUnknown
{
    //! Returns the total size of the payload this descriptor describes
    STDMETHOD_(UINT, GetPayloadSizeInBytes)() = 0;

    //! Gets a field by field id.
    STDMETHOD_(_Ret_maybenull_ const PERCEPTION_PAYLOAD_FIELD*, FindFieldById)(
        REFGUID fieldId) = 0;
};

MIDL_INTERFACE("{C2FB5866-1C71-4B74-89E1-EA13F2709B11}")
IPerceptionDeviceStateStream : public IUnknown
{
    //! Gets the payload descriptor. Does not fail, because the descriptor was read
    //! and validated during creation of the IPerceptionDeviceStateStream object.
    STDMETHOD_(__success(true) void, GetPayloadDescriptor)(
        _COM_Outptr_ IPerceptionDevicePayloadDescriptor** descriptor) = 0;

    //! Creates a reader for this state stream.
    STDMETHOD(CreateReader)(
        UINT subscriptionFlags,
        _COM_Outptr_ IPerceptionDeviceStateStreamReader** reader) = 0;
};

MIDL_INTERFACE("{3B84AAB1-D2BE-4D26-B285-E21CDE1DE058}")
IPerceptionDeviceStateStreamReader : public IUnknown
{
    //! Reads the next one or more states AFTER the specified timestamp into caller-supplied memory
    //! Reads into caller-allocated memory.
    //! bufferSize should be a multiple of the payload size.
    //! On output, *numBytesRead will be divisible by the payload size.
    STDMETHOD(ReadStatesAfterTime)(
        LONGLONG timestampInQpcTicks,
        UINT bufferSize,
        _Out_writes_bytes_to_(bufferSize, *numBytesRead) void* buffer,
        _Out_ UINT* numBytesRead) = 0;

    //! Reads up to 2 states around the specified time.
    //! Reads into caller-allocated memory.
    //! bufferSize should be a multiple of the payload size.
    //! On output, *numBytesRead will be divisible by the payload size.
    STDMETHOD(ReadStatesAroundTime)(
        LONGLONG timestampInQpcTicks,
        UINT bufferSize,
        _Out_writes_bytes_to_(bufferSize, *numBytesRead) void* buffer,
        _Out_ UINT* numBytesRead) = 0;
};

MIDL_INTERFACE("{9801651F-E62B-4E19-979F-4B8C5ADB80E6}")
IPerceptionDeviceObjectSubscription : public IUnknown
{
    //! Return the device used to create this subscription, and thus won't fail.
    STDMETHOD_(__success(true) void, GetDevice)(_COM_Outptr_ IPerceptionDevice** device) = 0;

    //! Returns the id of the object subscribed to.
    STDMETHOD_(REFGUID, GetObjectId)() = 0;

    //! Returns the subscription flags
    STDMETHOD_(UINT, GetSubscriptionFlags)() = 0;
};

MIDL_INTERFACE("{33D7A5EC-A087-4C8B-8167-67C0D6016FDB}")
IPerceptionDeviceFactory : public IUnknown
{
    //!
    //! Open a spatial object device with the specified device interface path
    //! and options.
    //!
    STDMETHOD(OpenDevice)(
        _In_z_ LPCWSTR deviceInterfacePath,
        PerceptionDeviceOptions options,
        _COM_Outptr_ IPerceptionDevice** device) = 0;

    //!
    //! Create an IPayloadDescriptor from a buffer.  For use when you need a payload descriptor
    //! without a state stream.  Makes a copy of the input buffer, so the caller does not need to keep the
    //! buffer alive after the method returns.
    //!
    STDMETHOD(CreatePayloadDescriptor)(
        UINT size,
        _In_bytecount_(size) const void* data,
        _COM_Outptr_ IPerceptionDevicePayloadDescriptor** descriptor) = 0;

    //!
    //! Create a watcher that watches for device arrival / removal,
    //! and for each device listens to the first of the specified
    //! properties that the device supports, and interpets the value as
    //! a GUID ObjectId.  It then invokes the callback
    //! for add / remove of {Device, ObjectId} pairs.
    //!
    //! If the device changes the value of the property to empty or a different
    //! GUID, the old {Device, ObjectId} pair will removed, and a new
    //! pair will be added.  This allows for the device to delay creation
    //! of top-level objects, shut them down, and bring them back up later.
    //!
    //! More than one PropertyId can be specified for back-compat purposes.
    //! For example, the caller that supports V1, V2, and V3 of SomeTracker
    //! would pass:
    //!     { PERCEPTIONPROP_SomeTrackerV3ObjectId,
    //!       PERCEPTIONPROP_SomeTrackerV2ObjectId,
    //!       PERCEPTIONPROP_SomeTrackerV1ObjectId }
    //!
    //! And then for any given device, it would only be informed of one top
    //! top-level object, preferring the newest version supported by the device.
    //!
    STDMETHOD(CreateRootObjectWatcher)(
        UINT propertyIdCount,
        _In_reads_(propertyIdCount) const GUID* propertyIds,
        PerceptionDeviceOptions deviceOptions,
        _COM_Outptr_ IPerceptionDeviceRootObjectWatcher** ppWatcher) = 0;
};

#endif /* WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_APP | WINAPI_PARTITION_GAMES) */
#endif /* NTDDI_VERSION >= NTDDI_WIN10_19H1 */
