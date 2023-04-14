// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Printers.Extensions.2.h"
#include "winrt/Windows.Devices.Printers.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::DeviceID() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->get_DeviceID(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::GetPrintModelPackage() const
{
    Windows::Foundation::IInspectable printModelPackage{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->GetPrintModelPackage(put_abi(printModelPackage)));
    return printModelPackage;
}

template <typename D> bool consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::IsPrintReady() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->get_IsPrintReady(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::IsPrintReady(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->put_IsPrintReady(value));
}

template <typename D> winrt::event_token consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::PrintRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::Print3DWorkflow, Windows::Devices::Printers::Extensions::Print3DWorkflowPrintRequestedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->add_PrintRequested(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::PrintRequested_revoker consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::PrintRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::Print3DWorkflow, Windows::Devices::Printers::Extensions::Print3DWorkflowPrintRequestedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, PrintRequested_revoker>(this, PrintRequested(eventHandler));
}

template <typename D> void consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::PrintRequested(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->remove_PrintRequested(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow2<D>::PrinterChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::Print3DWorkflow, Windows::Devices::Printers::Extensions::Print3DWorkflowPrinterChangedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflow2)->add_PrinterChanged(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow2<D>::PrinterChanged_revoker consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow2<D>::PrinterChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::Print3DWorkflow, Windows::Devices::Printers::Extensions::Print3DWorkflowPrinterChangedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, PrinterChanged_revoker>(this, PrinterChanged(eventHandler));
}

template <typename D> void consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow2<D>::PrinterChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflow2)->remove_PrinterChanged(get_abi(eventCookie)));
}

template <typename D> Windows::Devices::Printers::Extensions::Print3DWorkflowStatus consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflowPrintRequestedEventArgs<D>::Status() const
{
    Windows::Devices::Printers::Extensions::Print3DWorkflowStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflowPrintRequestedEventArgs<D>::SetExtendedStatus(Windows::Devices::Printers::Extensions::Print3DWorkflowDetail const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs)->SetExtendedStatus(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflowPrintRequestedEventArgs<D>::SetSource(Windows::Foundation::IInspectable const& source) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs)->SetSource(get_abi(source)));
}

template <typename D> void consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflowPrintRequestedEventArgs<D>::SetSourceChanged(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs)->SetSourceChanged(value));
}

template <typename D> hstring consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflowPrinterChangedEventArgs<D>::NewDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrinterChangedEventArgs)->get_NewDeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Devices_Printers_Extensions_IPrintExtensionContextStatic<D>::FromDeviceId(param::hstring const& deviceId) const
{
    Windows::Foundation::IInspectable context{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintExtensionContextStatic)->FromDeviceId(get_abi(deviceId), put_abi(context)));
    return context;
}

template <typename D> hstring consume_Windows_Devices_Printers_Extensions_IPrintNotificationEventDetails<D>::PrinterName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails)->get_PrinterName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Printers_Extensions_IPrintNotificationEventDetails<D>::EventData() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails)->get_EventData(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Printers_Extensions_IPrintNotificationEventDetails<D>::EventData(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails)->put_EventData(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Devices_Printers_Extensions_IPrintTaskConfiguration<D>::PrinterExtensionContext() const
{
    Windows::Foundation::IInspectable context{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintTaskConfiguration)->get_PrinterExtensionContext(put_abi(context)));
    return context;
}

template <typename D> winrt::event_token consume_Windows_Devices_Printers_Extensions_IPrintTaskConfiguration<D>::SaveRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::PrintTaskConfiguration, Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintTaskConfiguration)->add_SaveRequested(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Devices_Printers_Extensions_IPrintTaskConfiguration<D>::SaveRequested_revoker consume_Windows_Devices_Printers_Extensions_IPrintTaskConfiguration<D>::SaveRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::PrintTaskConfiguration, Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, SaveRequested_revoker>(this, SaveRequested(eventHandler));
}

template <typename D> void consume_Windows_Devices_Printers_Extensions_IPrintTaskConfiguration<D>::SaveRequested(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintTaskConfiguration)->remove_SaveRequested(get_abi(eventCookie)));
}

template <typename D> void consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequest<D>::Cancel() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest)->Cancel());
}

template <typename D> void consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequest<D>::Save(Windows::Foundation::IInspectable const& printerExtensionContext) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest)->Save(get_abi(printerExtensionContext)));
}

template <typename D> Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedDeferral consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequest<D>::GetDeferral() const
{
    Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequest<D>::Deadline() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest)->get_Deadline(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequestedDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedDeferral)->Complete());
}

template <typename D> Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequest consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequestedEventArgs<D>::Request() const
{
    Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequest context{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedEventArgs)->get_Request(put_abi(context)));
    return context;
}

template <typename D>
struct produce<D, Windows::Devices::Printers::Extensions::IPrint3DWorkflow> : produce_base<D, Windows::Devices::Printers::Extensions::IPrint3DWorkflow>
{
    int32_t WINRT_CALL get_DeviceID(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceID, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceID());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetPrintModelPackage(void** printModelPackage) noexcept final
    {
        try
        {
            *printModelPackage = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPrintModelPackage, WINRT_WRAP(Windows::Foundation::IInspectable));
            *printModelPackage = detach_from<Windows::Foundation::IInspectable>(this->shim().GetPrintModelPackage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsPrintReady(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPrintReady, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsPrintReady());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsPrintReady(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPrintReady, WINRT_WRAP(void), bool);
            this->shim().IsPrintReady(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_PrintRequested(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::Print3DWorkflow, Windows::Devices::Printers::Extensions::Print3DWorkflowPrintRequestedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().PrintRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::Print3DWorkflow, Windows::Devices::Printers::Extensions::Print3DWorkflowPrintRequestedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PrintRequested(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PrintRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PrintRequested(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Printers::Extensions::IPrint3DWorkflow2> : produce_base<D, Windows::Devices::Printers::Extensions::IPrint3DWorkflow2>
{
    int32_t WINRT_CALL add_PrinterChanged(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrinterChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::Print3DWorkflow, Windows::Devices::Printers::Extensions::Print3DWorkflowPrinterChangedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().PrinterChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::Print3DWorkflow, Windows::Devices::Printers::Extensions::Print3DWorkflowPrinterChangedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PrinterChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PrinterChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PrinterChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs> : produce_base<D, Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::Printers::Extensions::Print3DWorkflowStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Printers::Extensions::Print3DWorkflowStatus));
            *value = detach_from<Windows::Devices::Printers::Extensions::Print3DWorkflowStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetExtendedStatus(Windows::Devices::Printers::Extensions::Print3DWorkflowDetail value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetExtendedStatus, WINRT_WRAP(void), Windows::Devices::Printers::Extensions::Print3DWorkflowDetail const&);
            this->shim().SetExtendedStatus(*reinterpret_cast<Windows::Devices::Printers::Extensions::Print3DWorkflowDetail const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSource(void* source) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSource, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().SetSource(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetSourceChanged(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSourceChanged, WINRT_WRAP(void), bool);
            this->shim().SetSourceChanged(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrinterChangedEventArgs> : produce_base<D, Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrinterChangedEventArgs>
{
    int32_t WINRT_CALL get_NewDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NewDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NewDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Printers::Extensions::IPrintExtensionContextStatic> : produce_base<D, Windows::Devices::Printers::Extensions::IPrintExtensionContextStatic>
{
    int32_t WINRT_CALL FromDeviceId(void* deviceId, void** context) noexcept final
    {
        try
        {
            *context = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromDeviceId, WINRT_WRAP(Windows::Foundation::IInspectable), hstring const&);
            *context = detach_from<Windows::Foundation::IInspectable>(this->shim().FromDeviceId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails> : produce_base<D, Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails>
{
    int32_t WINRT_CALL get_PrinterName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrinterName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PrinterName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EventData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EventData, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EventData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_EventData(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EventData, WINRT_WRAP(void), hstring const&);
            this->shim().EventData(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Printers::Extensions::IPrintTaskConfiguration> : produce_base<D, Windows::Devices::Printers::Extensions::IPrintTaskConfiguration>
{
    int32_t WINRT_CALL get_PrinterExtensionContext(void** context) noexcept final
    {
        try
        {
            *context = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrinterExtensionContext, WINRT_WRAP(Windows::Foundation::IInspectable));
            *context = detach_from<Windows::Foundation::IInspectable>(this->shim().PrinterExtensionContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_SaveRequested(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::PrintTaskConfiguration, Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().SaveRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::Printers::Extensions::PrintTaskConfiguration, Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SaveRequested(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SaveRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SaveRequested(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest> : produce_base<D, Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest>
{
    int32_t WINRT_CALL Cancel() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void));
            this->shim().Cancel();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Save(void* printerExtensionContext) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Save, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Save(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&printerExtensionContext));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedDeferral));
            *deferral = detach_from<Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deadline, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedDeferral> : produce_base<D, Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedEventArgs> : produce_base<D, Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** context) noexcept final
    {
        try
        {
            *context = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequest));
            *context = detach_from<Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Printers::Extensions {

inline Windows::Foundation::IInspectable PrintExtensionContext::FromDeviceId(param::hstring const& deviceId)
{
    return impl::call_factory<PrintExtensionContext, Windows::Devices::Printers::Extensions::IPrintExtensionContextStatic>([&](auto&& f) { return f.FromDeviceId(deviceId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow2> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow2> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrinterChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrinterChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintExtensionContextStatic> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::IPrintExtensionContextStatic> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfiguration> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfiguration> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedDeferral> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedDeferral> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflow> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflow> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrintRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrintRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrinterChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrinterChangedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintExtensionContext> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::PrintExtensionContext> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintNotificationEventDetails> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::PrintNotificationEventDetails> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfiguration> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfiguration> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequest> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequest> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedDeferral> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedDeferral> {};
template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedEventArgs> {};

}
