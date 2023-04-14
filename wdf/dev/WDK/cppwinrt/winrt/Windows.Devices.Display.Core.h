// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Display.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.Graphics.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.Display.Core.2.h"
#include "winrt/Windows.Devices.Display.h"

namespace winrt::impl {

template <typename D> Windows::Graphics::DisplayAdapterId consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::Id() const
{
    Windows::Graphics::DisplayAdapterId value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayAdapter)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::DeviceInterfacePath() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayAdapter)->get_DeviceInterfacePath(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::SourceCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayAdapter)->get_SourceCount(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::PciVendorId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayAdapter)->get_PciVendorId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::PciDeviceId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayAdapter)->get_PciDeviceId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::PciSubSystemId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayAdapter)->get_PciSubSystemId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::PciRevision() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayAdapter)->get_PciRevision(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Devices_Display_Core_IDisplayAdapter<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayAdapter)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayAdapter consume_Windows_Devices_Display_Core_IDisplayAdapterStatics<D>::FromId(Windows::Graphics::DisplayAdapterId const& id) const
{
    Windows::Devices::Display::Core::DisplayAdapter result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayAdapterStatics)->FromId(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplaySource consume_Windows_Devices_Display_Core_IDisplayDevice<D>::CreateScanoutSource(Windows::Devices::Display::Core::DisplayTarget const& target) const
{
    Windows::Devices::Display::Core::DisplaySource result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayDevice)->CreateScanoutSource(get_abi(target), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplaySurface consume_Windows_Devices_Display_Core_IDisplayDevice<D>::CreatePrimary(Windows::Devices::Display::Core::DisplayTarget const& target, Windows::Devices::Display::Core::DisplayPrimaryDescription const& desc) const
{
    Windows::Devices::Display::Core::DisplaySurface result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayDevice)->CreatePrimary(get_abi(target), get_abi(desc), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayTaskPool consume_Windows_Devices_Display_Core_IDisplayDevice<D>::CreateTaskPool() const
{
    Windows::Devices::Display::Core::DisplayTaskPool result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayDevice)->CreateTaskPool(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayFence consume_Windows_Devices_Display_Core_IDisplayDevice<D>::CreatePeriodicFence(Windows::Devices::Display::Core::DisplayTarget const& target, Windows::Foundation::TimeSpan const& offsetFromVBlank) const
{
    Windows::Devices::Display::Core::DisplayFence result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayDevice)->CreatePeriodicFence(get_abi(target), get_abi(offsetFromVBlank), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayDevice<D>::WaitForVBlank(Windows::Devices::Display::Core::DisplaySource const& source) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayDevice)->WaitForVBlank(get_abi(source)));
}

template <typename D> Windows::Devices::Display::Core::DisplayScanout consume_Windows_Devices_Display_Core_IDisplayDevice<D>::CreateSimpleScanout(Windows::Devices::Display::Core::DisplaySource const& pSource, Windows::Devices::Display::Core::DisplaySurface const& pSurface, uint32_t SubResourceIndex, uint32_t SyncInterval) const
{
    Windows::Devices::Display::Core::DisplayScanout result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayDevice)->CreateSimpleScanout(get_abi(pSource), get_abi(pSurface), SubResourceIndex, SyncInterval, put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayDevice<D>::IsCapabilitySupported(Windows::Devices::Display::Core::DisplayDeviceCapability const& capability) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayDevice)->IsCapabilitySupported(get_abi(capability), &result));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayTarget> consume_Windows_Devices_Display_Core_IDisplayManager<D>::GetCurrentTargets() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayTarget> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->GetCurrentTargets(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayAdapter> consume_Windows_Devices_Display_Core_IDisplayManager<D>::GetCurrentAdapters() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayAdapter> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->GetCurrentAdapters(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayManagerResult consume_Windows_Devices_Display_Core_IDisplayManager<D>::TryAcquireTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const
{
    Windows::Devices::Display::Core::DisplayManagerResult result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->TryAcquireTarget(get_abi(target), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayManager<D>::ReleaseTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->ReleaseTarget(get_abi(target)));
}

template <typename D> Windows::Devices::Display::Core::DisplayManagerResultWithState consume_Windows_Devices_Display_Core_IDisplayManager<D>::TryReadCurrentStateForAllTargets() const
{
    Windows::Devices::Display::Core::DisplayManagerResultWithState result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->TryReadCurrentStateForAllTargets(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayManagerResultWithState consume_Windows_Devices_Display_Core_IDisplayManager<D>::TryAcquireTargetsAndReadCurrentState(param::iterable<Windows::Devices::Display::Core::DisplayTarget> const& targets) const
{
    Windows::Devices::Display::Core::DisplayManagerResultWithState result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->TryAcquireTargetsAndReadCurrentState(get_abi(targets), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayManagerResultWithState consume_Windows_Devices_Display_Core_IDisplayManager<D>::TryAcquireTargetsAndCreateEmptyState(param::iterable<Windows::Devices::Display::Core::DisplayTarget> const& targets) const
{
    Windows::Devices::Display::Core::DisplayManagerResultWithState result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->TryAcquireTargetsAndCreateEmptyState(get_abi(targets), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayManagerResultWithState consume_Windows_Devices_Display_Core_IDisplayManager<D>::TryAcquireTargetsAndCreateSubstate(Windows::Devices::Display::Core::DisplayState const& existingState, param::iterable<Windows::Devices::Display::Core::DisplayTarget> const& targets) const
{
    Windows::Devices::Display::Core::DisplayManagerResultWithState result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->TryAcquireTargetsAndCreateSubstate(get_abi(existingState), get_abi(targets), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayDevice consume_Windows_Devices_Display_Core_IDisplayManager<D>::CreateDisplayDevice(Windows::Devices::Display::Core::DisplayAdapter const& adapter) const
{
    Windows::Devices::Display::Core::DisplayDevice result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->CreateDisplayDevice(get_abi(adapter), put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Devices_Display_Core_IDisplayManager<D>::Enabled(Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->add_Enabled(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Display_Core_IDisplayManager<D>::Enabled_revoker consume_Windows_Devices_Display_Core_IDisplayManager<D>::Enabled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Enabled_revoker>(this, Enabled(handler));
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayManager<D>::Enabled(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->remove_Enabled(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Display_Core_IDisplayManager<D>::Disabled(Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->add_Disabled(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Display_Core_IDisplayManager<D>::Disabled_revoker consume_Windows_Devices_Display_Core_IDisplayManager<D>::Disabled(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Disabled_revoker>(this, Disabled(handler));
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayManager<D>::Disabled(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->remove_Disabled(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Display_Core_IDisplayManager<D>::Changed(Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->add_Changed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Display_Core_IDisplayManager<D>::Changed_revoker consume_Windows_Devices_Display_Core_IDisplayManager<D>::Changed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Changed_revoker>(this, Changed(handler));
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayManager<D>::Changed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->remove_Changed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Display_Core_IDisplayManager<D>::PathsFailedOrInvalidated(Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->add_PathsFailedOrInvalidated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Display_Core_IDisplayManager<D>::PathsFailedOrInvalidated_revoker consume_Windows_Devices_Display_Core_IDisplayManager<D>::PathsFailedOrInvalidated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, PathsFailedOrInvalidated_revoker>(this, PathsFailedOrInvalidated(handler));
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayManager<D>::PathsFailedOrInvalidated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->remove_PathsFailedOrInvalidated(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayManager<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->Start());
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayManager<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManager)->Stop());
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayManagerChangedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayManagerChangedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_Display_Core_IDisplayManagerChangedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayManagerDisabledEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayManagerDisabledEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_Display_Core_IDisplayManagerDisabledEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayManagerEnabledEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayManagerEnabledEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_Display_Core_IDisplayManagerEnabledEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayManagerPathsFailedOrInvalidatedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayManagerPathsFailedOrInvalidatedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_Display_Core_IDisplayManagerPathsFailedOrInvalidatedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayManagerResult consume_Windows_Devices_Display_Core_IDisplayManagerResultWithState<D>::ErrorCode() const
{
    Windows::Devices::Display::Core::DisplayManagerResult value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerResultWithState)->get_ErrorCode(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Devices_Display_Core_IDisplayManagerResultWithState<D>::ExtendedErrorCode() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerResultWithState)->get_ExtendedErrorCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayState consume_Windows_Devices_Display_Core_IDisplayManagerResultWithState<D>::State() const
{
    Windows::Devices::Display::Core::DisplayState value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerResultWithState)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayManager consume_Windows_Devices_Display_Core_IDisplayManagerStatics<D>::Create(Windows::Devices::Display::Core::DisplayManagerOptions const& options) const
{
    Windows::Devices::Display::Core::DisplayManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayManagerStatics)->Create(get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::SizeInt32 consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::SourceResolution() const
{
    Windows::Graphics::SizeInt32 value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayModeInfo)->get_SourceResolution(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::IsStereo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayModeInfo)->get_IsStereo(&value));
    return value;
}

template <typename D> Windows::Graphics::DirectX::DirectXPixelFormat consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::SourcePixelFormat() const
{
    Windows::Graphics::DirectX::DirectXPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayModeInfo)->get_SourcePixelFormat(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::SizeInt32 consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::TargetResolution() const
{
    Windows::Graphics::SizeInt32 value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayModeInfo)->get_TargetResolution(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayPresentationRate consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::PresentationRate() const
{
    Windows::Devices::Display::Core::DisplayPresentationRate value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayModeInfo)->get_PresentationRate(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::IsInterlaced() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayModeInfo)->get_IsInterlaced(&value));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayBitsPerChannel consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::GetWireFormatSupportedBitsPerChannel(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& encoding) const
{
    Windows::Devices::Display::Core::DisplayBitsPerChannel result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayModeInfo)->GetWireFormatSupportedBitsPerChannel(get_abi(encoding), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::IsWireFormatSupported(Windows::Devices::Display::Core::DisplayWireFormat const& wireFormat) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayModeInfo)->IsWireFormatSupported(get_abi(wireFormat), &result));
    return result;
}

template <typename D> Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Devices_Display_Core_IDisplayModeInfo<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayModeInfo)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayView consume_Windows_Devices_Display_Core_IDisplayPath<D>::View() const
{
    Windows::Devices::Display::Core::DisplayView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_View(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayTarget consume_Windows_Devices_Display_Core_IDisplayPath<D>::Target() const
{
    Windows::Devices::Display::Core::DisplayTarget value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_Target(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayPathStatus consume_Windows_Devices_Display_Core_IDisplayPath<D>::Status() const
{
    Windows::Devices::Display::Core::DisplayPathStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Graphics::SizeInt32> consume_Windows_Devices_Display_Core_IDisplayPath<D>::SourceResolution() const
{
    Windows::Foundation::IReference<Windows::Graphics::SizeInt32> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_SourceResolution(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayPath<D>::SourceResolution(optional<Windows::Graphics::SizeInt32> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->put_SourceResolution(get_abi(value)));
}

template <typename D> Windows::Graphics::DirectX::DirectXPixelFormat consume_Windows_Devices_Display_Core_IDisplayPath<D>::SourcePixelFormat() const
{
    Windows::Graphics::DirectX::DirectXPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_SourcePixelFormat(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayPath<D>::SourcePixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->put_SourcePixelFormat(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayPath<D>::IsStereo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_IsStereo(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayPath<D>::IsStereo(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->put_IsStereo(value));
}

template <typename D> Windows::Foundation::IReference<Windows::Graphics::SizeInt32> consume_Windows_Devices_Display_Core_IDisplayPath<D>::TargetResolution() const
{
    Windows::Foundation::IReference<Windows::Graphics::SizeInt32> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_TargetResolution(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayPath<D>::TargetResolution(optional<Windows::Graphics::SizeInt32> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->put_TargetResolution(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Devices::Display::Core::DisplayPresentationRate> consume_Windows_Devices_Display_Core_IDisplayPath<D>::PresentationRate() const
{
    Windows::Foundation::IReference<Windows::Devices::Display::Core::DisplayPresentationRate> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_PresentationRate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayPath<D>::PresentationRate(optional<Windows::Devices::Display::Core::DisplayPresentationRate> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->put_PresentationRate(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<bool> consume_Windows_Devices_Display_Core_IDisplayPath<D>::IsInterlaced() const
{
    Windows::Foundation::IReference<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_IsInterlaced(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayPath<D>::IsInterlaced(optional<bool> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->put_IsInterlaced(get_abi(value)));
}

template <typename D> Windows::Devices::Display::Core::DisplayWireFormat consume_Windows_Devices_Display_Core_IDisplayPath<D>::WireFormat() const
{
    Windows::Devices::Display::Core::DisplayWireFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_WireFormat(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayPath<D>::WireFormat(Windows::Devices::Display::Core::DisplayWireFormat const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->put_WireFormat(get_abi(value)));
}

template <typename D> Windows::Devices::Display::Core::DisplayRotation consume_Windows_Devices_Display_Core_IDisplayPath<D>::Rotation() const
{
    Windows::Devices::Display::Core::DisplayRotation value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_Rotation(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayPath<D>::Rotation(Windows::Devices::Display::Core::DisplayRotation const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->put_Rotation(get_abi(value)));
}

template <typename D> Windows::Devices::Display::Core::DisplayPathScaling consume_Windows_Devices_Display_Core_IDisplayPath<D>::Scaling() const
{
    Windows::Devices::Display::Core::DisplayPathScaling value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_Scaling(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayPath<D>::Scaling(Windows::Devices::Display::Core::DisplayPathScaling const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->put_Scaling(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayModeInfo> consume_Windows_Devices_Display_Core_IDisplayPath<D>::FindModes(Windows::Devices::Display::Core::DisplayModeQueryOptions const& flags) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayModeInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->FindModes(get_abi(flags), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayPath<D>::ApplyPropertiesFromMode(Windows::Devices::Display::Core::DisplayModeInfo const& modeResult) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->ApplyPropertiesFromMode(get_abi(modeResult)));
}

template <typename D> Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Devices_Display_Core_IDisplayPath<D>::Properties() const
{
    Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPath)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_Width(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_Height(&value));
    return value;
}

template <typename D> Windows::Graphics::DirectX::DirectXPixelFormat consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::Format() const
{
    Windows::Graphics::DirectX::DirectXPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_Format(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::DirectX::DirectXColorSpace consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::ColorSpace() const
{
    Windows::Graphics::DirectX::DirectXColorSpace value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_ColorSpace(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::IsStereo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_IsStereo(&value));
    return value;
}

template <typename D> Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::MultisampleDescription() const
{
    Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_MultisampleDescription(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Devices_Display_Core_IDisplayPrimaryDescription<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPrimaryDescription)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayPrimaryDescription consume_Windows_Devices_Display_Core_IDisplayPrimaryDescriptionFactory<D>::CreateInstance(uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription) const
{
    Windows::Devices::Display::Core::DisplayPrimaryDescription value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory)->CreateInstance(width, height, get_abi(pixelFormat), get_abi(colorSpace), isStereo, get_abi(multisampleDescription), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayPrimaryDescription consume_Windows_Devices_Display_Core_IDisplayPrimaryDescriptionStatics<D>::CreateWithProperties(param::iterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const& extraProperties, uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription) const
{
    Windows::Devices::Display::Core::DisplayPrimaryDescription result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics)->CreateWithProperties(get_abi(extraProperties), width, height, get_abi(pixelFormat), get_abi(colorSpace), isStereo, get_abi(multisampleDescription), put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::DisplayAdapterId consume_Windows_Devices_Display_Core_IDisplaySource<D>::AdapterId() const
{
    Windows::Graphics::DisplayAdapterId value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplaySource)->get_AdapterId(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Display_Core_IDisplaySource<D>::SourceId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplaySource)->get_SourceId(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_Display_Core_IDisplaySource<D>::GetMetadata(winrt::guid const& Key) const
{
    Windows::Storage::Streams::IBuffer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplaySource)->GetMetadata(get_abi(Key), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayState<D>::IsReadOnly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->get_IsReadOnly(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayState<D>::IsStale() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->get_IsStale(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayTarget> consume_Windows_Devices_Display_Core_IDisplayState<D>::Targets() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayTarget> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->get_Targets(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayView> consume_Windows_Devices_Display_Core_IDisplayState<D>::Views() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayView> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->get_Views(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Devices_Display_Core_IDisplayState<D>::Properties() const
{
    Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayPath consume_Windows_Devices_Display_Core_IDisplayState<D>::ConnectTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const
{
    Windows::Devices::Display::Core::DisplayPath result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->ConnectTarget(get_abi(target), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayPath consume_Windows_Devices_Display_Core_IDisplayState<D>::ConnectTarget(Windows::Devices::Display::Core::DisplayTarget const& target, Windows::Devices::Display::Core::DisplayView const& view) const
{
    Windows::Devices::Display::Core::DisplayPath result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->ConnectTargetToView(get_abi(target), get_abi(view), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayState<D>::CanConnectTargetToView(Windows::Devices::Display::Core::DisplayTarget const& target, Windows::Devices::Display::Core::DisplayView const& view) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->CanConnectTargetToView(get_abi(target), get_abi(view), &result));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayView consume_Windows_Devices_Display_Core_IDisplayState<D>::GetViewForTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const
{
    Windows::Devices::Display::Core::DisplayView result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->GetViewForTarget(get_abi(target), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayPath consume_Windows_Devices_Display_Core_IDisplayState<D>::GetPathForTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const
{
    Windows::Devices::Display::Core::DisplayPath result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->GetPathForTarget(get_abi(target), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayState<D>::DisconnectTarget(Windows::Devices::Display::Core::DisplayTarget const& target) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->DisconnectTarget(get_abi(target)));
}

template <typename D> Windows::Devices::Display::Core::DisplayStateOperationResult consume_Windows_Devices_Display_Core_IDisplayState<D>::TryFunctionalize(Windows::Devices::Display::Core::DisplayStateFunctionalizeOptions const& options) const
{
    Windows::Devices::Display::Core::DisplayStateOperationResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->TryFunctionalize(get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayStateOperationResult consume_Windows_Devices_Display_Core_IDisplayState<D>::TryApply(Windows::Devices::Display::Core::DisplayStateApplyOptions const& options) const
{
    Windows::Devices::Display::Core::DisplayStateOperationResult result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->TryApply(get_abi(options), put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayState consume_Windows_Devices_Display_Core_IDisplayState<D>::Clone() const
{
    Windows::Devices::Display::Core::DisplayState result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayState)->Clone(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Display::Core::DisplayStateOperationStatus consume_Windows_Devices_Display_Core_IDisplayStateOperationResult<D>::Status() const
{
    Windows::Devices::Display::Core::DisplayStateOperationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayStateOperationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> winrt::hresult consume_Windows_Devices_Display_Core_IDisplayStateOperationResult<D>::ExtendedErrorCode() const
{
    winrt::hresult value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayStateOperationResult)->get_ExtendedErrorCode(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayAdapter consume_Windows_Devices_Display_Core_IDisplayTarget<D>::Adapter() const
{
    Windows::Devices::Display::Core::DisplayAdapter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->get_Adapter(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Display_Core_IDisplayTarget<D>::DeviceInterfacePath() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->get_DeviceInterfacePath(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_Display_Core_IDisplayTarget<D>::AdapterRelativeId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->get_AdapterRelativeId(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsConnected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->get_IsConnected(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsVirtualModeEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->get_IsVirtualModeEnabled(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsVirtualTopologyEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->get_IsVirtualTopologyEnabled(&value));
    return value;
}

template <typename D> Windows::Devices::Display::DisplayMonitorUsageKind consume_Windows_Devices_Display_Core_IDisplayTarget<D>::UsageKind() const
{
    Windows::Devices::Display::DisplayMonitorUsageKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->get_UsageKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayTargetPersistence consume_Windows_Devices_Display_Core_IDisplayTarget<D>::MonitorPersistence() const
{
    Windows::Devices::Display::Core::DisplayTargetPersistence value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->get_MonitorPersistence(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Display_Core_IDisplayTarget<D>::StableMonitorId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->get_StableMonitorId(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::DisplayMonitor consume_Windows_Devices_Display_Core_IDisplayTarget<D>::TryGetMonitor() const
{
    Windows::Devices::Display::DisplayMonitor result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->TryGetMonitor(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Devices_Display_Core_IDisplayTarget<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsStale() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->get_IsStale(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsSame(Windows::Devices::Display::Core::DisplayTarget const& otherTarget) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->IsSame(get_abi(otherTarget), &result));
    return result;
}

template <typename D> bool consume_Windows_Devices_Display_Core_IDisplayTarget<D>::IsEqual(Windows::Devices::Display::Core::DisplayTarget const& otherTarget) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTarget)->IsEqual(get_abi(otherTarget), &result));
    return result;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayTask<D>::SetScanout(Windows::Devices::Display::Core::DisplayScanout const& scanout) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTask)->SetScanout(get_abi(scanout)));
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayTask<D>::SetWait(Windows::Devices::Display::Core::DisplayFence const& readyFence, uint64_t readyFenceValue) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTask)->SetWait(get_abi(readyFence), readyFenceValue));
}

template <typename D> Windows::Devices::Display::Core::DisplayTask consume_Windows_Devices_Display_Core_IDisplayTaskPool<D>::CreateTask() const
{
    Windows::Devices::Display::Core::DisplayTask result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTaskPool)->CreateTask(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayTaskPool<D>::ExecuteTask(Windows::Devices::Display::Core::DisplayTask const& task) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayTaskPool)->ExecuteTask(get_abi(task)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayPath> consume_Windows_Devices_Display_Core_IDisplayView<D>::Paths() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayPath> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayView)->get_Paths(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Graphics::SizeInt32> consume_Windows_Devices_Display_Core_IDisplayView<D>::ContentResolution() const
{
    Windows::Foundation::IReference<Windows::Graphics::SizeInt32> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayView)->get_ContentResolution(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayView<D>::ContentResolution(optional<Windows::Graphics::SizeInt32> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayView)->put_ContentResolution(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_Display_Core_IDisplayView<D>::SetPrimaryPath(Windows::Devices::Display::Core::DisplayPath const& path) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayView)->SetPrimaryPath(get_abi(path)));
}

template <typename D> Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Devices_Display_Core_IDisplayView<D>::Properties() const
{
    Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayView)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::PixelEncoding() const
{
    Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayWireFormat)->get_PixelEncoding(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::BitsPerChannel() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayWireFormat)->get_BitsPerChannel(&value));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayWireFormatColorSpace consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::ColorSpace() const
{
    Windows::Devices::Display::Core::DisplayWireFormatColorSpace value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayWireFormat)->get_ColorSpace(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayWireFormatEotf consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::Eotf() const
{
    Windows::Devices::Display::Core::DisplayWireFormatEotf value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayWireFormat)->get_Eotf(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::HdrMetadata() const
{
    Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayWireFormat)->get_HdrMetadata(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> consume_Windows_Devices_Display_Core_IDisplayWireFormat<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayWireFormat)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayWireFormat consume_Windows_Devices_Display_Core_IDisplayWireFormatFactory<D>::CreateInstance(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata) const
{
    Windows::Devices::Display::Core::DisplayWireFormat value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayWireFormatFactory)->CreateInstance(get_abi(pixelEncoding), bitsPerChannel, get_abi(colorSpace), get_abi(eotf), get_abi(hdrMetadata), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Display::Core::DisplayWireFormat consume_Windows_Devices_Display_Core_IDisplayWireFormatStatics<D>::CreateWithProperties(param::iterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const& extraProperties, Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata) const
{
    Windows::Devices::Display::Core::DisplayWireFormat result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Display::Core::IDisplayWireFormatStatics)->CreateWithProperties(get_abi(extraProperties), get_abi(pixelEncoding), bitsPerChannel, get_abi(colorSpace), get_abi(eotf), get_abi(hdrMetadata), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayAdapter> : produce_base<D, Windows::Devices::Display::Core::IDisplayAdapter>
{
    int32_t WINRT_CALL get_Id(struct struct_Windows_Graphics_DisplayAdapterId* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(Windows::Graphics::DisplayAdapterId));
            *value = detach_from<Windows::Graphics::DisplayAdapterId>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceInterfacePath(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceInterfacePath, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceInterfacePath());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SourceCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PciVendorId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PciVendorId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PciVendorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PciDeviceId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PciDeviceId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PciDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PciSubSystemId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PciSubSystemId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PciSubSystemId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PciRevision(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PciRevision, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().PciRevision());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayAdapterStatics> : produce_base<D, Windows::Devices::Display::Core::IDisplayAdapterStatics>
{
    int32_t WINRT_CALL FromId(struct struct_Windows_Graphics_DisplayAdapterId id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromId, WINRT_WRAP(Windows::Devices::Display::Core::DisplayAdapter), Windows::Graphics::DisplayAdapterId const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayAdapter>(this->shim().FromId(*reinterpret_cast<Windows::Graphics::DisplayAdapterId const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayDevice> : produce_base<D, Windows::Devices::Display::Core::IDisplayDevice>
{
    int32_t WINRT_CALL CreateScanoutSource(void* target, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateScanoutSource, WINRT_WRAP(Windows::Devices::Display::Core::DisplaySource), Windows::Devices::Display::Core::DisplayTarget const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplaySource>(this->shim().CreateScanoutSource(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePrimary(void* target, void* desc, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePrimary, WINRT_WRAP(Windows::Devices::Display::Core::DisplaySurface), Windows::Devices::Display::Core::DisplayTarget const&, Windows::Devices::Display::Core::DisplayPrimaryDescription const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplaySurface>(this->shim().CreatePrimary(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&target), *reinterpret_cast<Windows::Devices::Display::Core::DisplayPrimaryDescription const*>(&desc)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTaskPool(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTaskPool, WINRT_WRAP(Windows::Devices::Display::Core::DisplayTaskPool));
            *result = detach_from<Windows::Devices::Display::Core::DisplayTaskPool>(this->shim().CreateTaskPool());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreatePeriodicFence(void* target, Windows::Foundation::TimeSpan offsetFromVBlank, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreatePeriodicFence, WINRT_WRAP(Windows::Devices::Display::Core::DisplayFence), Windows::Devices::Display::Core::DisplayTarget const&, Windows::Foundation::TimeSpan const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayFence>(this->shim().CreatePeriodicFence(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&target), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&offsetFromVBlank)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL WaitForVBlank(void* source) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaitForVBlank, WINRT_WRAP(void), Windows::Devices::Display::Core::DisplaySource const&);
            this->shim().WaitForVBlank(*reinterpret_cast<Windows::Devices::Display::Core::DisplaySource const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSimpleScanout(void* pSource, void* pSurface, uint32_t SubResourceIndex, uint32_t SyncInterval, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSimpleScanout, WINRT_WRAP(Windows::Devices::Display::Core::DisplayScanout), Windows::Devices::Display::Core::DisplaySource const&, Windows::Devices::Display::Core::DisplaySurface const&, uint32_t, uint32_t);
            *result = detach_from<Windows::Devices::Display::Core::DisplayScanout>(this->shim().CreateSimpleScanout(*reinterpret_cast<Windows::Devices::Display::Core::DisplaySource const*>(&pSource), *reinterpret_cast<Windows::Devices::Display::Core::DisplaySurface const*>(&pSurface), SubResourceIndex, SyncInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsCapabilitySupported(Windows::Devices::Display::Core::DisplayDeviceCapability capability, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCapabilitySupported, WINRT_WRAP(bool), Windows::Devices::Display::Core::DisplayDeviceCapability const&);
            *result = detach_from<bool>(this->shim().IsCapabilitySupported(*reinterpret_cast<Windows::Devices::Display::Core::DisplayDeviceCapability const*>(&capability)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayFence> : produce_base<D, Windows::Devices::Display::Core::IDisplayFence>
{};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayManager> : produce_base<D, Windows::Devices::Display::Core::IDisplayManager>
{
    int32_t WINRT_CALL GetCurrentTargets(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentTargets, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayTarget>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayTarget>>(this->shim().GetCurrentTargets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentAdapters(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentAdapters, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayAdapter>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayAdapter>>(this->shim().GetCurrentAdapters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryAcquireTarget(void* target, Windows::Devices::Display::Core::DisplayManagerResult* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryAcquireTarget, WINRT_WRAP(Windows::Devices::Display::Core::DisplayManagerResult), Windows::Devices::Display::Core::DisplayTarget const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayManagerResult>(this->shim().TryAcquireTarget(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReleaseTarget(void* target) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReleaseTarget, WINRT_WRAP(void), Windows::Devices::Display::Core::DisplayTarget const&);
            this->shim().ReleaseTarget(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryReadCurrentStateForAllTargets(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryReadCurrentStateForAllTargets, WINRT_WRAP(Windows::Devices::Display::Core::DisplayManagerResultWithState));
            *result = detach_from<Windows::Devices::Display::Core::DisplayManagerResultWithState>(this->shim().TryReadCurrentStateForAllTargets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryAcquireTargetsAndReadCurrentState(void* targets, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryAcquireTargetsAndReadCurrentState, WINRT_WRAP(Windows::Devices::Display::Core::DisplayManagerResultWithState), Windows::Foundation::Collections::IIterable<Windows::Devices::Display::Core::DisplayTarget> const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayManagerResultWithState>(this->shim().TryAcquireTargetsAndReadCurrentState(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Display::Core::DisplayTarget> const*>(&targets)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryAcquireTargetsAndCreateEmptyState(void* targets, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryAcquireTargetsAndCreateEmptyState, WINRT_WRAP(Windows::Devices::Display::Core::DisplayManagerResultWithState), Windows::Foundation::Collections::IIterable<Windows::Devices::Display::Core::DisplayTarget> const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayManagerResultWithState>(this->shim().TryAcquireTargetsAndCreateEmptyState(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Display::Core::DisplayTarget> const*>(&targets)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryAcquireTargetsAndCreateSubstate(void* existingState, void* targets, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryAcquireTargetsAndCreateSubstate, WINRT_WRAP(Windows::Devices::Display::Core::DisplayManagerResultWithState), Windows::Devices::Display::Core::DisplayState const&, Windows::Foundation::Collections::IIterable<Windows::Devices::Display::Core::DisplayTarget> const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayManagerResultWithState>(this->shim().TryAcquireTargetsAndCreateSubstate(*reinterpret_cast<Windows::Devices::Display::Core::DisplayState const*>(&existingState), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Display::Core::DisplayTarget> const*>(&targets)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateDisplayDevice(void* adapter, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateDisplayDevice, WINRT_WRAP(Windows::Devices::Display::Core::DisplayDevice), Windows::Devices::Display::Core::DisplayAdapter const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayDevice>(this->shim().CreateDisplayDevice(*reinterpret_cast<Windows::Devices::Display::Core::DisplayAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Enabled(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Enabled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Enabled(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Enabled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Enabled(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Disabled(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disabled, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Disabled(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Disabled(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Disabled, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Disabled(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Changed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Changed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Changed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Changed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Changed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PathsFailedOrInvalidated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PathsFailedOrInvalidated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().PathsFailedOrInvalidated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Display::Core::DisplayManager, Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PathsFailedOrInvalidated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PathsFailedOrInvalidated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PathsFailedOrInvalidated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL Start() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Start, WINRT_WRAP(void));
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Stop() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stop, WINRT_WRAP(void));
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs> : produce_base<D, Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs> : produce_base<D, Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs> : produce_base<D, Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs> : produce_base<D, Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs>
{
    int32_t WINRT_CALL get_Handled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Handled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Handled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Handled, WINRT_WRAP(void), bool);
            this->shim().Handled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *result = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayManagerResultWithState> : produce_base<D, Windows::Devices::Display::Core::IDisplayManagerResultWithState>
{
    int32_t WINRT_CALL get_ErrorCode(Windows::Devices::Display::Core::DisplayManagerResult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ErrorCode, WINRT_WRAP(Windows::Devices::Display::Core::DisplayManagerResult));
            *value = detach_from<Windows::Devices::Display::Core::DisplayManagerResult>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedErrorCode(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedErrorCode, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Devices::Display::Core::DisplayState));
            *value = detach_from<Windows::Devices::Display::Core::DisplayState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayManagerStatics> : produce_base<D, Windows::Devices::Display::Core::IDisplayManagerStatics>
{
    int32_t WINRT_CALL Create(Windows::Devices::Display::Core::DisplayManagerOptions options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Display::Core::DisplayManager), Windows::Devices::Display::Core::DisplayManagerOptions const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayManager>(this->shim().Create(*reinterpret_cast<Windows::Devices::Display::Core::DisplayManagerOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayModeInfo> : produce_base<D, Windows::Devices::Display::Core::IDisplayModeInfo>
{
    int32_t WINRT_CALL get_SourceResolution(struct struct_Windows_Graphics_SizeInt32* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceResolution, WINRT_WRAP(Windows::Graphics::SizeInt32));
            *value = detach_from<Windows::Graphics::SizeInt32>(this->shim().SourceResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStereo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStereo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStereo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourcePixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePixelFormat, WINRT_WRAP(Windows::Graphics::DirectX::DirectXPixelFormat));
            *value = detach_from<Windows::Graphics::DirectX::DirectXPixelFormat>(this->shim().SourcePixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetResolution(struct struct_Windows_Graphics_SizeInt32* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetResolution, WINRT_WRAP(Windows::Graphics::SizeInt32));
            *value = detach_from<Windows::Graphics::SizeInt32>(this->shim().TargetResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PresentationRate(struct struct_Windows_Devices_Display_Core_DisplayPresentationRate* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentationRate, WINRT_WRAP(Windows::Devices::Display::Core::DisplayPresentationRate));
            *value = detach_from<Windows::Devices::Display::Core::DisplayPresentationRate>(this->shim().PresentationRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInterlaced(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInterlaced, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsInterlaced());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetWireFormatSupportedBitsPerChannel(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding encoding, Windows::Devices::Display::Core::DisplayBitsPerChannel* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetWireFormatSupportedBitsPerChannel, WINRT_WRAP(Windows::Devices::Display::Core::DisplayBitsPerChannel), Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayBitsPerChannel>(this->shim().GetWireFormatSupportedBitsPerChannel(*reinterpret_cast<Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const*>(&encoding)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsWireFormatSupported(void* wireFormat, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWireFormatSupported, WINRT_WRAP(bool), Windows::Devices::Display::Core::DisplayWireFormat const&);
            *result = detach_from<bool>(this->shim().IsWireFormatSupported(*reinterpret_cast<Windows::Devices::Display::Core::DisplayWireFormat const*>(&wireFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayPath> : produce_base<D, Windows::Devices::Display::Core::IDisplayPath>
{
    int32_t WINRT_CALL get_View(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(View, WINRT_WRAP(Windows::Devices::Display::Core::DisplayView));
            *value = detach_from<Windows::Devices::Display::Core::DisplayView>(this->shim().View());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Target(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Target, WINRT_WRAP(Windows::Devices::Display::Core::DisplayTarget));
            *value = detach_from<Windows::Devices::Display::Core::DisplayTarget>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Devices::Display::Core::DisplayPathStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Display::Core::DisplayPathStatus));
            *value = detach_from<Windows::Devices::Display::Core::DisplayPathStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceResolution(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceResolution, WINRT_WRAP(Windows::Foundation::IReference<Windows::Graphics::SizeInt32>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Graphics::SizeInt32>>(this->shim().SourceResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourceResolution(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceResolution, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Graphics::SizeInt32> const&);
            this->shim().SourceResolution(*reinterpret_cast<Windows::Foundation::IReference<Windows::Graphics::SizeInt32> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourcePixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePixelFormat, WINRT_WRAP(Windows::Graphics::DirectX::DirectXPixelFormat));
            *value = detach_from<Windows::Graphics::DirectX::DirectXPixelFormat>(this->shim().SourcePixelFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SourcePixelFormat(Windows::Graphics::DirectX::DirectXPixelFormat value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePixelFormat, WINRT_WRAP(void), Windows::Graphics::DirectX::DirectXPixelFormat const&);
            this->shim().SourcePixelFormat(*reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStereo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStereo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStereo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsStereo(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStereo, WINRT_WRAP(void), bool);
            this->shim().IsStereo(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetResolution(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetResolution, WINRT_WRAP(Windows::Foundation::IReference<Windows::Graphics::SizeInt32>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Graphics::SizeInt32>>(this->shim().TargetResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetResolution(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetResolution, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Graphics::SizeInt32> const&);
            this->shim().TargetResolution(*reinterpret_cast<Windows::Foundation::IReference<Windows::Graphics::SizeInt32> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PresentationRate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentationRate, WINRT_WRAP(Windows::Foundation::IReference<Windows::Devices::Display::Core::DisplayPresentationRate>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Devices::Display::Core::DisplayPresentationRate>>(this->shim().PresentationRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PresentationRate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PresentationRate, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Devices::Display::Core::DisplayPresentationRate> const&);
            this->shim().PresentationRate(*reinterpret_cast<Windows::Foundation::IReference<Windows::Devices::Display::Core::DisplayPresentationRate> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsInterlaced(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInterlaced, WINRT_WRAP(Windows::Foundation::IReference<bool>));
            *value = detach_from<Windows::Foundation::IReference<bool>>(this->shim().IsInterlaced());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsInterlaced(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsInterlaced, WINRT_WRAP(void), Windows::Foundation::IReference<bool> const&);
            this->shim().IsInterlaced(*reinterpret_cast<Windows::Foundation::IReference<bool> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WireFormat(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WireFormat, WINRT_WRAP(Windows::Devices::Display::Core::DisplayWireFormat));
            *value = detach_from<Windows::Devices::Display::Core::DisplayWireFormat>(this->shim().WireFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WireFormat(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WireFormat, WINRT_WRAP(void), Windows::Devices::Display::Core::DisplayWireFormat const&);
            this->shim().WireFormat(*reinterpret_cast<Windows::Devices::Display::Core::DisplayWireFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Rotation(Windows::Devices::Display::Core::DisplayRotation* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(Windows::Devices::Display::Core::DisplayRotation));
            *value = detach_from<Windows::Devices::Display::Core::DisplayRotation>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Rotation(Windows::Devices::Display::Core::DisplayRotation value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Rotation, WINRT_WRAP(void), Windows::Devices::Display::Core::DisplayRotation const&);
            this->shim().Rotation(*reinterpret_cast<Windows::Devices::Display::Core::DisplayRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scaling(Windows::Devices::Display::Core::DisplayPathScaling* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scaling, WINRT_WRAP(Windows::Devices::Display::Core::DisplayPathScaling));
            *value = detach_from<Windows::Devices::Display::Core::DisplayPathScaling>(this->shim().Scaling());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Scaling(Windows::Devices::Display::Core::DisplayPathScaling value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scaling, WINRT_WRAP(void), Windows::Devices::Display::Core::DisplayPathScaling const&);
            this->shim().Scaling(*reinterpret_cast<Windows::Devices::Display::Core::DisplayPathScaling const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindModes(Windows::Devices::Display::Core::DisplayModeQueryOptions flags, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindModes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayModeInfo>), Windows::Devices::Display::Core::DisplayModeQueryOptions const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayModeInfo>>(this->shim().FindModes(*reinterpret_cast<Windows::Devices::Display::Core::DisplayModeQueryOptions const*>(&flags)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ApplyPropertiesFromMode(void* modeResult) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApplyPropertiesFromMode, WINRT_WRAP(void), Windows::Devices::Display::Core::DisplayModeInfo const&);
            this->shim().ApplyPropertiesFromMode(*reinterpret_cast<Windows::Devices::Display::Core::DisplayModeInfo const*>(&modeResult));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayPrimaryDescription> : produce_base<D, Windows::Devices::Display::Core::IDisplayPrimaryDescription>
{
    int32_t WINRT_CALL get_Width(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Height(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Format(Windows::Graphics::DirectX::DirectXPixelFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(Windows::Graphics::DirectX::DirectXPixelFormat));
            *value = detach_from<Windows::Graphics::DirectX::DirectXPixelFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorSpace(Windows::Graphics::DirectX::DirectXColorSpace* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorSpace, WINRT_WRAP(Windows::Graphics::DirectX::DirectXColorSpace));
            *value = detach_from<Windows::Graphics::DirectX::DirectXColorSpace>(this->shim().ColorSpace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStereo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStereo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStereo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MultisampleDescription(struct struct_Windows_Graphics_DirectX_Direct3D11_Direct3DMultisampleDescription* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MultisampleDescription, WINRT_WRAP(Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription));
            *value = detach_from<Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription>(this->shim().MultisampleDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory> : produce_base<D, Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory>
{
    int32_t WINRT_CALL CreateInstance(uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace colorSpace, bool isStereo, struct struct_Windows_Graphics_DirectX_Direct3D11_Direct3DMultisampleDescription multisampleDescription, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Devices::Display::Core::DisplayPrimaryDescription), uint32_t, uint32_t, Windows::Graphics::DirectX::DirectXPixelFormat const&, Windows::Graphics::DirectX::DirectXColorSpace const&, bool, Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const&);
            *value = detach_from<Windows::Devices::Display::Core::DisplayPrimaryDescription>(this->shim().CreateInstance(width, height, *reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat), *reinterpret_cast<Windows::Graphics::DirectX::DirectXColorSpace const*>(&colorSpace), isStereo, *reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const*>(&multisampleDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics> : produce_base<D, Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics>
{
    int32_t WINRT_CALL CreateWithProperties(void* extraProperties, uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace colorSpace, bool isStereo, struct struct_Windows_Graphics_DirectX_Direct3D11_Direct3DMultisampleDescription multisampleDescription, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithProperties, WINRT_WRAP(Windows::Devices::Display::Core::DisplayPrimaryDescription), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const&, uint32_t, uint32_t, Windows::Graphics::DirectX::DirectXPixelFormat const&, Windows::Graphics::DirectX::DirectXColorSpace const&, bool, Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayPrimaryDescription>(this->shim().CreateWithProperties(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const*>(&extraProperties), width, height, *reinterpret_cast<Windows::Graphics::DirectX::DirectXPixelFormat const*>(&pixelFormat), *reinterpret_cast<Windows::Graphics::DirectX::DirectXColorSpace const*>(&colorSpace), isStereo, *reinterpret_cast<Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const*>(&multisampleDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayScanout> : produce_base<D, Windows::Devices::Display::Core::IDisplayScanout>
{};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplaySource> : produce_base<D, Windows::Devices::Display::Core::IDisplaySource>
{
    int32_t WINRT_CALL get_AdapterId(struct struct_Windows_Graphics_DisplayAdapterId* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdapterId, WINRT_WRAP(Windows::Graphics::DisplayAdapterId));
            *value = detach_from<Windows::Graphics::DisplayAdapterId>(this->shim().AdapterId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().SourceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetMetadata(winrt::guid Key, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetMetadata, WINRT_WRAP(Windows::Storage::Streams::IBuffer), winrt::guid const&);
            *result = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().GetMetadata(*reinterpret_cast<winrt::guid const*>(&Key)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayState> : produce_base<D, Windows::Devices::Display::Core::IDisplayState>
{
    int32_t WINRT_CALL get_IsReadOnly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsReadOnly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsReadOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStale(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStale, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Targets(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Targets, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayTarget>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayTarget>>(this->shim().Targets());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Views(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Views, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayView>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayView>>(this->shim().Views());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectTarget(void* target, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectTarget, WINRT_WRAP(Windows::Devices::Display::Core::DisplayPath), Windows::Devices::Display::Core::DisplayTarget const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayPath>(this->shim().ConnectTarget(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectTargetToView(void* target, void* view, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectTarget, WINRT_WRAP(Windows::Devices::Display::Core::DisplayPath), Windows::Devices::Display::Core::DisplayTarget const&, Windows::Devices::Display::Core::DisplayView const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayPath>(this->shim().ConnectTarget(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&target), *reinterpret_cast<Windows::Devices::Display::Core::DisplayView const*>(&view)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CanConnectTargetToView(void* target, void* view, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanConnectTargetToView, WINRT_WRAP(bool), Windows::Devices::Display::Core::DisplayTarget const&, Windows::Devices::Display::Core::DisplayView const&);
            *result = detach_from<bool>(this->shim().CanConnectTargetToView(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&target), *reinterpret_cast<Windows::Devices::Display::Core::DisplayView const*>(&view)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetViewForTarget(void* target, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetViewForTarget, WINRT_WRAP(Windows::Devices::Display::Core::DisplayView), Windows::Devices::Display::Core::DisplayTarget const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayView>(this->shim().GetViewForTarget(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPathForTarget(void* target, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPathForTarget, WINRT_WRAP(Windows::Devices::Display::Core::DisplayPath), Windows::Devices::Display::Core::DisplayTarget const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayPath>(this->shim().GetPathForTarget(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DisconnectTarget(void* target) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisconnectTarget, WINRT_WRAP(void), Windows::Devices::Display::Core::DisplayTarget const&);
            this->shim().DisconnectTarget(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryFunctionalize(Windows::Devices::Display::Core::DisplayStateFunctionalizeOptions options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryFunctionalize, WINRT_WRAP(Windows::Devices::Display::Core::DisplayStateOperationResult), Windows::Devices::Display::Core::DisplayStateFunctionalizeOptions const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayStateOperationResult>(this->shim().TryFunctionalize(*reinterpret_cast<Windows::Devices::Display::Core::DisplayStateFunctionalizeOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryApply(Windows::Devices::Display::Core::DisplayStateApplyOptions options, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryApply, WINRT_WRAP(Windows::Devices::Display::Core::DisplayStateOperationResult), Windows::Devices::Display::Core::DisplayStateApplyOptions const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayStateOperationResult>(this->shim().TryApply(*reinterpret_cast<Windows::Devices::Display::Core::DisplayStateApplyOptions const*>(&options)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clone(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clone, WINRT_WRAP(Windows::Devices::Display::Core::DisplayState));
            *result = detach_from<Windows::Devices::Display::Core::DisplayState>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayStateOperationResult> : produce_base<D, Windows::Devices::Display::Core::IDisplayStateOperationResult>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Display::Core::DisplayStateOperationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Display::Core::DisplayStateOperationStatus));
            *value = detach_from<Windows::Devices::Display::Core::DisplayStateOperationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedErrorCode(winrt::hresult* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedErrorCode, WINRT_WRAP(winrt::hresult));
            *value = detach_from<winrt::hresult>(this->shim().ExtendedErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplaySurface> : produce_base<D, Windows::Devices::Display::Core::IDisplaySurface>
{};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayTarget> : produce_base<D, Windows::Devices::Display::Core::IDisplayTarget>
{
    int32_t WINRT_CALL get_Adapter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Adapter, WINRT_WRAP(Windows::Devices::Display::Core::DisplayAdapter));
            *value = detach_from<Windows::Devices::Display::Core::DisplayAdapter>(this->shim().Adapter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceInterfacePath(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceInterfacePath, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceInterfacePath());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdapterRelativeId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdapterRelativeId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().AdapterRelativeId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsConnected(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConnected, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsConnected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsVirtualModeEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVirtualModeEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVirtualModeEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsVirtualTopologyEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVirtualTopologyEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVirtualTopologyEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UsageKind(Windows::Devices::Display::DisplayMonitorUsageKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UsageKind, WINRT_WRAP(Windows::Devices::Display::DisplayMonitorUsageKind));
            *value = detach_from<Windows::Devices::Display::DisplayMonitorUsageKind>(this->shim().UsageKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MonitorPersistence(Windows::Devices::Display::Core::DisplayTargetPersistence* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MonitorPersistence, WINRT_WRAP(Windows::Devices::Display::Core::DisplayTargetPersistence));
            *value = detach_from<Windows::Devices::Display::Core::DisplayTargetPersistence>(this->shim().MonitorPersistence());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StableMonitorId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StableMonitorId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().StableMonitorId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetMonitor(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetMonitor, WINRT_WRAP(Windows::Devices::Display::DisplayMonitor));
            *result = detach_from<Windows::Devices::Display::DisplayMonitor>(this->shim().TryGetMonitor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStale(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStale, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsSame(void* otherTarget, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSame, WINRT_WRAP(bool), Windows::Devices::Display::Core::DisplayTarget const&);
            *result = detach_from<bool>(this->shim().IsSame(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&otherTarget)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsEqual(void* otherTarget, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEqual, WINRT_WRAP(bool), Windows::Devices::Display::Core::DisplayTarget const&);
            *result = detach_from<bool>(this->shim().IsEqual(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTarget const*>(&otherTarget)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayTask> : produce_base<D, Windows::Devices::Display::Core::IDisplayTask>
{
    int32_t WINRT_CALL SetScanout(void* scanout) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetScanout, WINRT_WRAP(void), Windows::Devices::Display::Core::DisplayScanout const&);
            this->shim().SetScanout(*reinterpret_cast<Windows::Devices::Display::Core::DisplayScanout const*>(&scanout));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetWait(void* readyFence, uint64_t readyFenceValue) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetWait, WINRT_WRAP(void), Windows::Devices::Display::Core::DisplayFence const&, uint64_t);
            this->shim().SetWait(*reinterpret_cast<Windows::Devices::Display::Core::DisplayFence const*>(&readyFence), readyFenceValue);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayTaskPool> : produce_base<D, Windows::Devices::Display::Core::IDisplayTaskPool>
{
    int32_t WINRT_CALL CreateTask(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTask, WINRT_WRAP(Windows::Devices::Display::Core::DisplayTask));
            *result = detach_from<Windows::Devices::Display::Core::DisplayTask>(this->shim().CreateTask());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ExecuteTask(void* task) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExecuteTask, WINRT_WRAP(void), Windows::Devices::Display::Core::DisplayTask const&);
            this->shim().ExecuteTask(*reinterpret_cast<Windows::Devices::Display::Core::DisplayTask const*>(&task));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayView> : produce_base<D, Windows::Devices::Display::Core::IDisplayView>
{
    int32_t WINRT_CALL get_Paths(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Paths, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayPath>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Display::Core::DisplayPath>>(this->shim().Paths());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentResolution(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentResolution, WINRT_WRAP(Windows::Foundation::IReference<Windows::Graphics::SizeInt32>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Graphics::SizeInt32>>(this->shim().ContentResolution());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentResolution(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentResolution, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Graphics::SizeInt32> const&);
            this->shim().ContentResolution(*reinterpret_cast<Windows::Foundation::IReference<Windows::Graphics::SizeInt32> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetPrimaryPath(void* path) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetPrimaryPath, WINRT_WRAP(void), Windows::Devices::Display::Core::DisplayPath const&);
            this->shim().SetPrimaryPath(*reinterpret_cast<Windows::Devices::Display::Core::DisplayPath const*>(&path));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMap<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayWireFormat> : produce_base<D, Windows::Devices::Display::Core::IDisplayWireFormat>
{
    int32_t WINRT_CALL get_PixelEncoding(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelEncoding, WINRT_WRAP(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding));
            *value = detach_from<Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding>(this->shim().PixelEncoding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BitsPerChannel(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitsPerChannel, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().BitsPerChannel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorSpace(Windows::Devices::Display::Core::DisplayWireFormatColorSpace* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorSpace, WINRT_WRAP(Windows::Devices::Display::Core::DisplayWireFormatColorSpace));
            *value = detach_from<Windows::Devices::Display::Core::DisplayWireFormatColorSpace>(this->shim().ColorSpace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Eotf(Windows::Devices::Display::Core::DisplayWireFormatEotf* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Eotf, WINRT_WRAP(Windows::Devices::Display::Core::DisplayWireFormatEotf));
            *value = detach_from<Windows::Devices::Display::Core::DisplayWireFormatEotf>(this->shim().Eotf());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HdrMetadata(Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HdrMetadata, WINRT_WRAP(Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata));
            *value = detach_from<Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata>(this->shim().HdrMetadata());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<winrt::guid, Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayWireFormatFactory> : produce_base<D, Windows::Devices::Display::Core::IDisplayWireFormatFactory>
{
    int32_t WINRT_CALL CreateInstance(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata hdrMetadata, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::Devices::Display::Core::DisplayWireFormat), Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const&, int32_t, Windows::Devices::Display::Core::DisplayWireFormatColorSpace const&, Windows::Devices::Display::Core::DisplayWireFormatEotf const&, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const&);
            *value = detach_from<Windows::Devices::Display::Core::DisplayWireFormat>(this->shim().CreateInstance(*reinterpret_cast<Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const*>(&pixelEncoding), bitsPerChannel, *reinterpret_cast<Windows::Devices::Display::Core::DisplayWireFormatColorSpace const*>(&colorSpace), *reinterpret_cast<Windows::Devices::Display::Core::DisplayWireFormatEotf const*>(&eotf), *reinterpret_cast<Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const*>(&hdrMetadata)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Display::Core::IDisplayWireFormatStatics> : produce_base<D, Windows::Devices::Display::Core::IDisplayWireFormatStatics>
{
    int32_t WINRT_CALL CreateWithProperties(void* extraProperties, Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata hdrMetadata, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithProperties, WINRT_WRAP(Windows::Devices::Display::Core::DisplayWireFormat), Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const&, Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const&, int32_t, Windows::Devices::Display::Core::DisplayWireFormatColorSpace const&, Windows::Devices::Display::Core::DisplayWireFormatEotf const&, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const&);
            *result = detach_from<Windows::Devices::Display::Core::DisplayWireFormat>(this->shim().CreateWithProperties(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const*>(&extraProperties), *reinterpret_cast<Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const*>(&pixelEncoding), bitsPerChannel, *reinterpret_cast<Windows::Devices::Display::Core::DisplayWireFormatColorSpace const*>(&colorSpace), *reinterpret_cast<Windows::Devices::Display::Core::DisplayWireFormatEotf const*>(&eotf), *reinterpret_cast<Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const*>(&hdrMetadata)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Display::Core {

inline Windows::Devices::Display::Core::DisplayAdapter DisplayAdapter::FromId(Windows::Graphics::DisplayAdapterId const& id)
{
    return impl::call_factory<DisplayAdapter, Windows::Devices::Display::Core::IDisplayAdapterStatics>([&](auto&& f) { return f.FromId(id); });
}

inline Windows::Devices::Display::Core::DisplayManager DisplayManager::Create(Windows::Devices::Display::Core::DisplayManagerOptions const& options)
{
    return impl::call_factory<DisplayManager, Windows::Devices::Display::Core::IDisplayManagerStatics>([&](auto&& f) { return f.Create(options); });
}

inline DisplayPrimaryDescription::DisplayPrimaryDescription(uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription) :
    DisplayPrimaryDescription(impl::call_factory<DisplayPrimaryDescription, Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory>([&](auto&& f) { return f.CreateInstance(width, height, pixelFormat, colorSpace, isStereo, multisampleDescription); }))
{}

inline Windows::Devices::Display::Core::DisplayPrimaryDescription DisplayPrimaryDescription::CreateWithProperties(param::iterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const& extraProperties, uint32_t width, uint32_t height, Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, Windows::Graphics::DirectX::DirectXColorSpace const& colorSpace, bool isStereo, Windows::Graphics::DirectX::Direct3D11::Direct3DMultisampleDescription const& multisampleDescription)
{
    return impl::call_factory<DisplayPrimaryDescription, Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics>([&](auto&& f) { return f.CreateWithProperties(extraProperties, width, height, pixelFormat, colorSpace, isStereo, multisampleDescription); });
}

inline DisplayWireFormat::DisplayWireFormat(Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata) :
    DisplayWireFormat(impl::call_factory<DisplayWireFormat, Windows::Devices::Display::Core::IDisplayWireFormatFactory>([&](auto&& f) { return f.CreateInstance(pixelEncoding, bitsPerChannel, colorSpace, eotf, hdrMetadata); }))
{}

inline Windows::Devices::Display::Core::DisplayWireFormat DisplayWireFormat::CreateWithProperties(param::iterable<Windows::Foundation::Collections::IKeyValuePair<winrt::guid, Windows::Foundation::IInspectable>> const& extraProperties, Windows::Devices::Display::Core::DisplayWireFormatPixelEncoding const& pixelEncoding, int32_t bitsPerChannel, Windows::Devices::Display::Core::DisplayWireFormatColorSpace const& colorSpace, Windows::Devices::Display::Core::DisplayWireFormatEotf const& eotf, Windows::Devices::Display::Core::DisplayWireFormatHdrMetadata const& hdrMetadata)
{
    return impl::call_factory<DisplayWireFormat, Windows::Devices::Display::Core::IDisplayWireFormatStatics>([&](auto&& f) { return f.CreateWithProperties(extraProperties, pixelEncoding, bitsPerChannel, colorSpace, eotf, hdrMetadata); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayAdapter> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayAdapter> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayAdapterStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayAdapterStatics> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayDevice> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayFence> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayFence> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManager> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayManager> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayManagerChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayManagerDisabledEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayManagerEnabledEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayManagerPathsFailedOrInvalidatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerResultWithState> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayManagerResultWithState> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayManagerStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayManagerStatics> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayModeInfo> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayModeInfo> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayPath> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayPath> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescription> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionFactory> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayPrimaryDescriptionStatics> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayScanout> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayScanout> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplaySource> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplaySource> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayState> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayState> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayStateOperationResult> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayStateOperationResult> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplaySurface> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplaySurface> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayTarget> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayTarget> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayTask> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayTask> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayTaskPool> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayTaskPool> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayView> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayView> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayWireFormat> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayWireFormat> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayWireFormatFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayWireFormatFactory> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::IDisplayWireFormatStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::IDisplayWireFormatStatics> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayAdapter> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayAdapter> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayDevice> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayDevice> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayFence> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayFence> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManager> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayManager> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayManagerChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayManagerDisabledEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayManagerEnabledEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayManagerPathsFailedOrInvalidatedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayManagerResultWithState> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayModeInfo> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayModeInfo> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayPath> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayPath> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayPrimaryDescription> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayPrimaryDescription> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayScanout> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayScanout> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplaySource> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplaySource> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayState> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayState> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayStateOperationResult> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayStateOperationResult> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplaySurface> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplaySurface> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayTarget> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayTarget> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayTask> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayTask> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayTaskPool> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayTaskPool> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayView> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayView> {};
template<> struct hash<winrt::Windows::Devices::Display::Core::DisplayWireFormat> : winrt::impl::hash_base<winrt::Windows::Devices::Display::Core::DisplayWireFormat> {};

}
