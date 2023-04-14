// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.Web.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.Web.UI.2.h"
#include "winrt/impl/Windows.Web.UI.Interop.2.h"
#include "winrt/Windows.Web.UI.h"

namespace winrt::impl {

template <typename D> Windows::UI::Core::CoreAcceleratorKeyEventType consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::EventType() const
{
    Windows::UI::Core::CoreAcceleratorKeyEventType value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->get_EventType(put_abi(value)));
    return value;
}

template <typename D> Windows::System::VirtualKey consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::VirtualKey() const
{
    Windows::System::VirtualKey value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->get_VirtualKey(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Core::CorePhysicalKeyStatus consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::KeyStatus() const
{
    Windows::UI::Core::CorePhysicalKeyStatus value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->get_KeyStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::RoutingStage() const
{
    Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->get_RoutingStage(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::Handled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->get_Handled(&value));
    return value;
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlAcceleratorKeyPressedEventArgs<D>::Handled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs)->put_Handled(value));
}

template <typename D> Windows::Web::UI::Interop::WebViewControlMoveFocusReason consume_Windows_Web_UI_Interop_IWebViewControlMoveFocusRequestedEventArgs<D>::Reason() const
{
    Windows::Web::UI::Interop::WebViewControlMoveFocusReason value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs)->get_Reason(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::ProcessId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcess)->get_ProcessId(&value));
    return value;
}

template <typename D> hstring consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::EnterpriseId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcess)->get_EnterpriseId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::IsPrivateNetworkClientServerCapabilityEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcess)->get_IsPrivateNetworkClientServerCapabilityEnabled(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Web::UI::Interop::WebViewControl> consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::CreateWebViewControlAsync(int64_t hostWindowHandle, Windows::Foundation::Rect const& bounds) const
{
    Windows::Foundation::IAsyncOperation<Windows::Web::UI::Interop::WebViewControl> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcess)->CreateWebViewControlAsync(hostWindowHandle, get_abi(bounds), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Web::UI::Interop::WebViewControl> consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::GetWebViewControls() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Web::UI::Interop::WebViewControl> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcess)->GetWebViewControls(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::Terminate() const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcess)->Terminate());
}

template <typename D> winrt::event_token consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::ProcessExited(Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControlProcess, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcess)->add_ProcessExited(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::ProcessExited_revoker consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::ProcessExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControlProcess, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ProcessExited_revoker>(this, ProcessExited(handler));
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlProcess<D>::ProcessExited(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcess)->remove_ProcessExited(get_abi(token)));
}

template <typename D> Windows::Web::UI::Interop::WebViewControlProcess consume_Windows_Web_UI_Interop_IWebViewControlProcessFactory<D>::CreateWithOptions(Windows::Web::UI::Interop::WebViewControlProcessOptions const& processOptions) const
{
    Windows::Web::UI::Interop::WebViewControlProcess result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcessFactory)->CreateWithOptions(get_abi(processOptions), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlProcessOptions<D>::EnterpriseId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcessOptions)->put_EnterpriseId(get_abi(value)));
}

template <typename D> hstring consume_Windows_Web_UI_Interop_IWebViewControlProcessOptions<D>::EnterpriseId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcessOptions)->get_EnterpriseId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlProcessOptions<D>::PrivateNetworkClientServerCapability(Windows::Web::UI::Interop::WebViewControlProcessCapabilityState const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcessOptions)->put_PrivateNetworkClientServerCapability(get_abi(value)));
}

template <typename D> Windows::Web::UI::Interop::WebViewControlProcessCapabilityState consume_Windows_Web_UI_Interop_IWebViewControlProcessOptions<D>::PrivateNetworkClientServerCapability() const
{
    Windows::Web::UI::Interop::WebViewControlProcessCapabilityState value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlProcessOptions)->get_PrivateNetworkClientServerCapability(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::UI::Interop::WebViewControlProcess consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Process() const
{
    Windows::Web::UI::Interop::WebViewControlProcess value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->get_Process(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Scale(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->put_Scale(value));
}

template <typename D> double consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Scale() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->get_Scale(&value));
    return value;
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Bounds(Windows::Foundation::Rect const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->put_Bounds(get_abi(value)));
}

template <typename D> Windows::Foundation::Rect consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Bounds() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->get_Bounds(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::IsVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->put_IsVisible(value));
}

template <typename D> bool consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::IsVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->get_IsVisible(&value));
    return value;
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::Close() const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->Close());
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::MoveFocus(Windows::Web::UI::Interop::WebViewControlMoveFocusReason const& reason) const
{
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->MoveFocus(get_abi(reason)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::MoveFocusRequested(Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->add_MoveFocusRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::MoveFocusRequested_revoker consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::MoveFocusRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MoveFocusRequested_revoker>(this, MoveFocusRequested(handler));
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::MoveFocusRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->remove_MoveFocusRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::AcceleratorKeyPressed(Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->add_AcceleratorKeyPressed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::AcceleratorKeyPressed_revoker consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::AcceleratorKeyPressed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AcceleratorKeyPressed_revoker>(this, AcceleratorKeyPressed(handler));
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlSite<D>::AcceleratorKeyPressed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite)->remove_AcceleratorKeyPressed(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::GotFocus(Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite2)->add_GotFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::GotFocus_revoker consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::GotFocus(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, GotFocus_revoker>(this, GotFocus(handler));
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::GotFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite2)->remove_GotFocus(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::LostFocus(Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite2)->add_LostFocus(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::LostFocus_revoker consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::LostFocus(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, LostFocus_revoker>(this, LostFocus(handler));
}

template <typename D> void consume_Windows_Web_UI_Interop_IWebViewControlSite2<D>::LostFocus(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::UI::Interop::IWebViewControlSite2)->remove_LostFocus(get_abi(token)));
}

template <typename D>
struct produce<D, Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs> : produce_base<D, Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs>
{
    int32_t WINRT_CALL get_EventType(Windows::UI::Core::CoreAcceleratorKeyEventType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EventType, WINRT_WRAP(Windows::UI::Core::CoreAcceleratorKeyEventType));
            *value = detach_from<Windows::UI::Core::CoreAcceleratorKeyEventType>(this->shim().EventType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VirtualKey(Windows::System::VirtualKey* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VirtualKey, WINRT_WRAP(Windows::System::VirtualKey));
            *value = detach_from<Windows::System::VirtualKey>(this->shim().VirtualKey());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_KeyStatus(struct struct_Windows_UI_Core_CorePhysicalKeyStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(KeyStatus, WINRT_WRAP(Windows::UI::Core::CorePhysicalKeyStatus));
            *value = detach_from<Windows::UI::Core::CorePhysicalKeyStatus>(this->shim().KeyStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoutingStage(Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoutingStage, WINRT_WRAP(Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage));
            *value = detach_from<Windows::Web::UI::Interop::WebViewControlAcceleratorKeyRoutingStage>(this->shim().RoutingStage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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
};

template <typename D>
struct produce<D, Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs> : produce_base<D, Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs>
{
    int32_t WINRT_CALL get_Reason(Windows::Web::UI::Interop::WebViewControlMoveFocusReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reason, WINRT_WRAP(Windows::Web::UI::Interop::WebViewControlMoveFocusReason));
            *value = detach_from<Windows::Web::UI::Interop::WebViewControlMoveFocusReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::Interop::IWebViewControlProcess> : produce_base<D, Windows::Web::UI::Interop::IWebViewControlProcess>
{
    int32_t WINRT_CALL get_ProcessId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ProcessId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnterpriseId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnterpriseId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EnterpriseId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPrivateNetworkClientServerCapabilityEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPrivateNetworkClientServerCapabilityEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPrivateNetworkClientServerCapabilityEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWebViewControlAsync(int64_t hostWindowHandle, Windows::Foundation::Rect bounds, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWebViewControlAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Web::UI::Interop::WebViewControl>), int64_t, Windows::Foundation::Rect const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Web::UI::Interop::WebViewControl>>(this->shim().CreateWebViewControlAsync(hostWindowHandle, *reinterpret_cast<Windows::Foundation::Rect const*>(&bounds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetWebViewControls(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetWebViewControls, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Web::UI::Interop::WebViewControl>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Web::UI::Interop::WebViewControl>>(this->shim().GetWebViewControls());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Terminate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Terminate, WINRT_WRAP(void));
            this->shim().Terminate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ProcessExited(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProcessExited, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControlProcess, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ProcessExited(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControlProcess, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ProcessExited(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ProcessExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ProcessExited(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::Interop::IWebViewControlProcessFactory> : produce_base<D, Windows::Web::UI::Interop::IWebViewControlProcessFactory>
{
    int32_t WINRT_CALL CreateWithOptions(void* processOptions, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithOptions, WINRT_WRAP(Windows::Web::UI::Interop::WebViewControlProcess), Windows::Web::UI::Interop::WebViewControlProcessOptions const&);
            *result = detach_from<Windows::Web::UI::Interop::WebViewControlProcess>(this->shim().CreateWithOptions(*reinterpret_cast<Windows::Web::UI::Interop::WebViewControlProcessOptions const*>(&processOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::Interop::IWebViewControlProcessOptions> : produce_base<D, Windows::Web::UI::Interop::IWebViewControlProcessOptions>
{
    int32_t WINRT_CALL put_EnterpriseId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnterpriseId, WINRT_WRAP(void), hstring const&);
            this->shim().EnterpriseId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnterpriseId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnterpriseId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EnterpriseId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PrivateNetworkClientServerCapability(Windows::Web::UI::Interop::WebViewControlProcessCapabilityState value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrivateNetworkClientServerCapability, WINRT_WRAP(void), Windows::Web::UI::Interop::WebViewControlProcessCapabilityState const&);
            this->shim().PrivateNetworkClientServerCapability(*reinterpret_cast<Windows::Web::UI::Interop::WebViewControlProcessCapabilityState const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrivateNetworkClientServerCapability(Windows::Web::UI::Interop::WebViewControlProcessCapabilityState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrivateNetworkClientServerCapability, WINRT_WRAP(Windows::Web::UI::Interop::WebViewControlProcessCapabilityState));
            *value = detach_from<Windows::Web::UI::Interop::WebViewControlProcessCapabilityState>(this->shim().PrivateNetworkClientServerCapability());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::Interop::IWebViewControlSite> : produce_base<D, Windows::Web::UI::Interop::IWebViewControlSite>
{
    int32_t WINRT_CALL get_Process(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Process, WINRT_WRAP(Windows::Web::UI::Interop::WebViewControlProcess));
            *value = detach_from<Windows::Web::UI::Interop::WebViewControlProcess>(this->shim().Process());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Scale(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(void), double);
            this->shim().Scale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scale(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Bounds(Windows::Foundation::Rect value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(void), Windows::Foundation::Rect const&);
            this->shim().Bounds(*reinterpret_cast<Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bounds(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().Bounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVisible, WINRT_WRAP(void), bool);
            this->shim().IsVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Close() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Close, WINRT_WRAP(void));
            this->shim().Close();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveFocus(Windows::Web::UI::Interop::WebViewControlMoveFocusReason reason) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveFocus, WINRT_WRAP(void), Windows::Web::UI::Interop::WebViewControlMoveFocusReason const&);
            this->shim().MoveFocus(*reinterpret_cast<Windows::Web::UI::Interop::WebViewControlMoveFocusReason const*>(&reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MoveFocusRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveFocusRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MoveFocusRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MoveFocusRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MoveFocusRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MoveFocusRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_AcceleratorKeyPressed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcceleratorKeyPressed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().AcceleratorKeyPressed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AcceleratorKeyPressed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AcceleratorKeyPressed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AcceleratorKeyPressed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Web::UI::Interop::IWebViewControlSite2> : produce_base<D, Windows::Web::UI::Interop::IWebViewControlSite2>
{
    int32_t WINRT_CALL add_GotFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().GotFocus(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GotFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GotFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GotFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LostFocus(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().LostFocus(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::UI::Interop::WebViewControl, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LostFocus(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LostFocus, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LostFocus(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Web::UI::Interop {

inline WebViewControlProcess::WebViewControlProcess() :
    WebViewControlProcess(impl::call_factory<WebViewControlProcess>([](auto&& f) { return f.template ActivateInstance<WebViewControlProcess>(); }))
{}

inline WebViewControlProcess::WebViewControlProcess(Windows::Web::UI::Interop::WebViewControlProcessOptions const& processOptions) :
    WebViewControlProcess(impl::call_factory<WebViewControlProcess, Windows::Web::UI::Interop::IWebViewControlProcessFactory>([&](auto&& f) { return f.CreateWithOptions(processOptions); }))
{}

inline WebViewControlProcessOptions::WebViewControlProcessOptions() :
    WebViewControlProcessOptions(impl::call_factory<WebViewControlProcessOptions>([](auto&& f) { return f.template ActivateInstance<WebViewControlProcessOptions>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::IWebViewControlAcceleratorKeyPressedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::IWebViewControlMoveFocusRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlProcess> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::IWebViewControlProcess> {};
template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlProcessFactory> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::IWebViewControlProcessFactory> {};
template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::IWebViewControlProcessOptions> {};
template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlSite> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::IWebViewControlSite> {};
template<> struct hash<winrt::Windows::Web::UI::Interop::IWebViewControlSite2> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::IWebViewControlSite2> {};
template<> struct hash<winrt::Windows::Web::UI::Interop::WebViewControl> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::WebViewControl> {};
template<> struct hash<winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::WebViewControlAcceleratorKeyPressedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::WebViewControlMoveFocusRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Web::UI::Interop::WebViewControlProcess> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::WebViewControlProcess> {};
template<> struct hash<winrt::Windows::Web::UI::Interop::WebViewControlProcessOptions> : winrt::impl::hash_base<winrt::Windows::Web::UI::Interop::WebViewControlProcessOptions> {};

}
