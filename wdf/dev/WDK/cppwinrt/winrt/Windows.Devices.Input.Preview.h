// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.HumanInterfaceDevice.2.h"
#include "winrt/impl/Windows.Devices.Input.Preview.2.h"
#include "winrt/Windows.Devices.Input.h"

namespace winrt::impl {

template <typename D> uint32_t consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDevicePreview)->get_Id(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::CanTrackEyes() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDevicePreview)->get_CanTrackEyes(&value));
    return value;
}

template <typename D> bool consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::CanTrackHead() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDevicePreview)->get_CanTrackHead(&value));
    return value;
}

template <typename D> Windows::Devices::Input::Preview::GazeDeviceConfigurationStatePreview consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::ConfigurationState() const
{
    Windows::Devices::Input::Preview::GazeDeviceConfigurationStatePreview value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDevicePreview)->get_ConfigurationState(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::RequestCalibrationAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDevicePreview)->RequestCalibrationAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription> consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::GetNumericControlDescriptions(uint16_t usagePage, uint16_t usageId) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDevicePreview)->GetNumericControlDescriptions(usagePage, usageId, put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription> consume_Windows_Devices_Input_Preview_IGazeDevicePreview<D>::GetBooleanControlDescriptions(uint16_t usagePage, uint16_t usageId) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDevicePreview)->GetBooleanControlDescriptions(usagePage, usageId, put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Input::Preview::GazeDevicePreview consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherAddedPreviewEventArgs<D>::Device() const
{
    Windows::Devices::Input::Preview::GazeDevicePreview value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs)->get_Device(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Added(Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Added_revoker consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Removed(Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->add_Removed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Removed_revoker consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Removed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Removed_revoker>(this, Removed(handler));
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Removed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->remove_Removed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Updated(Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->add_Updated(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Updated_revoker consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Updated(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Updated(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->remove_Updated(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::EnumerationCompleted_revoker consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->Start());
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherPreview<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview)->Stop());
}

template <typename D> Windows::Devices::Input::Preview::GazeDevicePreview consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherRemovedPreviewEventArgs<D>::Device() const
{
    Windows::Devices::Input::Preview::GazeDevicePreview value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs)->get_Device(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Input::Preview::GazeDevicePreview consume_Windows_Devices_Input_Preview_IGazeDeviceWatcherUpdatedPreviewEventArgs<D>::Device() const
{
    Windows::Devices::Input::Preview::GazeDevicePreview value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs)->get_Device(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Input_Preview_IGazeEnteredPreviewEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeEnteredPreviewEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs)->put_Handled(value));
}

template <typename D> Windows::Devices::Input::Preview::GazePointPreview consume_Windows_Devices_Input_Preview_IGazeEnteredPreviewEventArgs<D>::CurrentPoint() const
{
    Windows::Devices::Input::Preview::GazePointPreview value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs)->get_CurrentPoint(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_Input_Preview_IGazeExitedPreviewEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeExitedPreviewEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs)->put_Handled(value));
}

template <typename D> Windows::Devices::Input::Preview::GazePointPreview consume_Windows_Devices_Input_Preview_IGazeExitedPreviewEventArgs<D>::CurrentPoint() const
{
    Windows::Devices::Input::Preview::GazePointPreview value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs)->get_CurrentPoint(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeMoved(Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeInputSourcePreview)->add_GazeMoved(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeMoved_revoker consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeMoved(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, GazeMoved_revoker>(this, GazeMoved(handler));
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeMoved(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Input::Preview::IGazeInputSourcePreview)->remove_GazeMoved(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeEntered(Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeInputSourcePreview)->add_GazeEntered(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeEntered_revoker consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeEntered(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, GazeEntered_revoker>(this, GazeEntered(handler));
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeEntered(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Input::Preview::IGazeInputSourcePreview)->remove_GazeEntered(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeExited(Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeInputSourcePreview)->add_GazeExited(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeExited_revoker consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, GazeExited_revoker>(this, GazeExited(handler));
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeInputSourcePreview<D>::GazeExited(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Input::Preview::IGazeInputSourcePreview)->remove_GazeExited(get_abi(token)));
}

template <typename D> Windows::Devices::Input::Preview::GazeInputSourcePreview consume_Windows_Devices_Input_Preview_IGazeInputSourcePreviewStatics<D>::GetForCurrentView() const
{
    Windows::Devices::Input::Preview::GazeInputSourcePreview result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics)->GetForCurrentView(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Input::Preview::GazeDeviceWatcherPreview consume_Windows_Devices_Input_Preview_IGazeInputSourcePreviewStatics<D>::CreateWatcher() const
{
    Windows::Devices::Input::Preview::GazeDeviceWatcherPreview result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics)->CreateWatcher(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_Input_Preview_IGazeMovedPreviewEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Input_Preview_IGazeMovedPreviewEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs)->put_Handled(value));
}

template <typename D> Windows::Devices::Input::Preview::GazePointPreview consume_Windows_Devices_Input_Preview_IGazeMovedPreviewEventArgs<D>::CurrentPoint() const
{
    Windows::Devices::Input::Preview::GazePointPreview value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs)->get_CurrentPoint(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Input::Preview::GazePointPreview> consume_Windows_Devices_Input_Preview_IGazeMovedPreviewEventArgs<D>::GetIntermediatePoints() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Input::Preview::GazePointPreview> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs)->GetIntermediatePoints(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Input::Preview::GazeDevicePreview consume_Windows_Devices_Input_Preview_IGazePointPreview<D>::SourceDevice() const
{
    Windows::Devices::Input::Preview::GazeDevicePreview value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazePointPreview)->get_SourceDevice(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Point> consume_Windows_Devices_Input_Preview_IGazePointPreview<D>::EyeGazePosition() const
{
    Windows::Foundation::IReference<Windows::Foundation::Point> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazePointPreview)->get_EyeGazePosition(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::Point> consume_Windows_Devices_Input_Preview_IGazePointPreview<D>::HeadGazePosition() const
{
    Windows::Foundation::IReference<Windows::Foundation::Point> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazePointPreview)->get_HeadGazePosition(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Devices_Input_Preview_IGazePointPreview<D>::Timestamp() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazePointPreview)->get_Timestamp(&value));
    return value;
}

template <typename D> Windows::Devices::HumanInterfaceDevice::HidInputReport consume_Windows_Devices_Input_Preview_IGazePointPreview<D>::HidInputReport() const
{
    Windows::Devices::HumanInterfaceDevice::HidInputReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Input::Preview::IGazePointPreview)->get_HidInputReport(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::Input::Preview::IGazeDevicePreview> : produce_base<D, Windows::Devices::Input::Preview::IGazeDevicePreview>
{
    int32_t WINRT_CALL get_Id(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanTrackEyes(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanTrackEyes, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanTrackEyes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanTrackHead(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanTrackHead, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanTrackHead());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConfigurationState(Windows::Devices::Input::Preview::GazeDeviceConfigurationStatePreview* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConfigurationState, WINRT_WRAP(Windows::Devices::Input::Preview::GazeDeviceConfigurationStatePreview));
            *value = detach_from<Windows::Devices::Input::Preview::GazeDeviceConfigurationStatePreview>(this->shim().ConfigurationState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestCalibrationAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestCalibrationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestCalibrationAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNumericControlDescriptions(uint16_t usagePage, uint16_t usageId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNumericControlDescriptions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription>), uint16_t, uint16_t);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidNumericControlDescription>>(this->shim().GetNumericControlDescriptions(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetBooleanControlDescriptions(uint16_t usagePage, uint16_t usageId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBooleanControlDescriptions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription>), uint16_t, uint16_t);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::HumanInterfaceDevice::HidBooleanControlDescription>>(this->shim().GetBooleanControlDescriptions(usagePage, usageId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs> : produce_base<D, Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs>
{
    int32_t WINRT_CALL get_Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Device, WINRT_WRAP(Windows::Devices::Input::Preview::GazeDevicePreview));
            *value = detach_from<Windows::Devices::Input::Preview::GazeDevicePreview>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview> : produce_base<D, Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview>
{
    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Added(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Added(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Removed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Removed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Removed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Removed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Removed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Updated(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Updated(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Updated, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnumerationCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnumerationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
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
struct produce<D, Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs> : produce_base<D, Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs>
{
    int32_t WINRT_CALL get_Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Device, WINRT_WRAP(Windows::Devices::Input::Preview::GazeDevicePreview));
            *value = detach_from<Windows::Devices::Input::Preview::GazeDevicePreview>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs> : produce_base<D, Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs>
{
    int32_t WINRT_CALL get_Device(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Device, WINRT_WRAP(Windows::Devices::Input::Preview::GazeDevicePreview));
            *value = detach_from<Windows::Devices::Input::Preview::GazeDevicePreview>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs> : produce_base<D, Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs>
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

    int32_t WINRT_CALL get_CurrentPoint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentPoint, WINRT_WRAP(Windows::Devices::Input::Preview::GazePointPreview));
            *value = detach_from<Windows::Devices::Input::Preview::GazePointPreview>(this->shim().CurrentPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs> : produce_base<D, Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs>
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

    int32_t WINRT_CALL get_CurrentPoint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentPoint, WINRT_WRAP(Windows::Devices::Input::Preview::GazePointPreview));
            *value = detach_from<Windows::Devices::Input::Preview::GazePointPreview>(this->shim().CurrentPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::Preview::IGazeInputSourcePreview> : produce_base<D, Windows::Devices::Input::Preview::IGazeInputSourcePreview>
{
    int32_t WINRT_CALL add_GazeMoved(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GazeMoved, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().GazeMoved(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GazeMoved(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GazeMoved, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GazeMoved(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GazeEntered(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GazeEntered, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().GazeEntered(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GazeEntered(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GazeEntered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GazeEntered(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GazeExited(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GazeExited, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().GazeExited(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Input::Preview::GazeInputSourcePreview, Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GazeExited(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GazeExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GazeExited(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics> : produce_base<D, Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::Devices::Input::Preview::GazeInputSourcePreview));
            *result = detach_from<Windows::Devices::Input::Preview::GazeInputSourcePreview>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWatcher(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWatcher, WINRT_WRAP(Windows::Devices::Input::Preview::GazeDeviceWatcherPreview));
            *result = detach_from<Windows::Devices::Input::Preview::GazeDeviceWatcherPreview>(this->shim().CreateWatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs> : produce_base<D, Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs>
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

    int32_t WINRT_CALL get_CurrentPoint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentPoint, WINRT_WRAP(Windows::Devices::Input::Preview::GazePointPreview));
            *value = detach_from<Windows::Devices::Input::Preview::GazePointPreview>(this->shim().CurrentPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIntermediatePoints(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIntermediatePoints, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Input::Preview::GazePointPreview>));
            *result = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Input::Preview::GazePointPreview>>(this->shim().GetIntermediatePoints());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Input::Preview::IGazePointPreview> : produce_base<D, Windows::Devices::Input::Preview::IGazePointPreview>
{
    int32_t WINRT_CALL get_SourceDevice(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceDevice, WINRT_WRAP(Windows::Devices::Input::Preview::GazeDevicePreview));
            *value = detach_from<Windows::Devices::Input::Preview::GazeDevicePreview>(this->shim().SourceDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EyeGazePosition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EyeGazePosition, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Point>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Point>>(this->shim().EyeGazePosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeadGazePosition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeadGazePosition, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::Point>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::Point>>(this->shim().HeadGazePosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamp(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HidInputReport(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HidInputReport, WINRT_WRAP(Windows::Devices::HumanInterfaceDevice::HidInputReport));
            *value = detach_from<Windows::Devices::HumanInterfaceDevice::HidInputReport>(this->shim().HidInputReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Input::Preview {

inline Windows::Devices::Input::Preview::GazeInputSourcePreview GazeInputSourcePreview::GetForCurrentView()
{
    return impl::call_factory<GazeInputSourcePreview, Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::Devices::Input::Preview::GazeDeviceWatcherPreview GazeInputSourcePreview::CreateWatcher()
{
    return impl::call_factory<GazeInputSourcePreview, Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics>([&](auto&& f) { return f.CreateWatcher(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeDevicePreview> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::IGazeDevicePreview> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherAddedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherPreview> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherRemovedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::IGazeDeviceWatcherUpdatedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::IGazeEnteredPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::IGazeExitedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreview> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreview> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::IGazeInputSourcePreviewStatics> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::IGazeMovedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::IGazePointPreview> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::IGazePointPreview> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeDevicePreview> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::GazeDevicePreview> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherAddedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherPreview> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherRemovedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::GazeDeviceWatcherUpdatedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::GazeEnteredPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::GazeExitedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::GazeInputSourcePreview> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::GazeMovedPreviewEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Input::Preview::GazePointPreview> : winrt::impl::hash_base<winrt::Windows::Devices::Input::Preview::GazePointPreview> {};

}
