// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Activation.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.Printing.PrintTicket.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.Graphics.Printing.Workflow.2.h"
#include "winrt/Windows.Graphics.Printing.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>::SetupRequested(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs> const& setupEventHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession)->add_SetupRequested(get_abi(setupEventHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>::SetupRequested_revoker consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>::SetupRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs> const& setupEventHandler) const
{
    return impl::make_event_revoker<D, SetupRequested_revoker>(this, SetupRequested(setupEventHandler));
}

template <typename D> void consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>::SetupRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession)->remove_SetupRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>::Submitted(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs> const& submittedEventHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession)->add_Submitted(get_abi(submittedEventHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>::Submitted_revoker consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>::Submitted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs> const& submittedEventHandler) const
{
    return impl::make_event_revoker<D, Submitted_revoker>(this, Submitted(submittedEventHandler));
}

template <typename D> void consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>::Submitted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession)->remove_Submitted(get_abi(token)));
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>::Status() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSession<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession)->Start());
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket> consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSetupRequestedEventArgs<D>::GetUserPrintTicketAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs)->GetUserPrintTicketAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSetupRequestedEventArgs<D>::Configuration() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration configuration{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs)->get_Configuration(put_abi(configuration)));
    return configuration;
}

template <typename D> void consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSetupRequestedEventArgs<D>::SetRequiresUI() const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs)->SetRequiresUI());
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowBackgroundSetupRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowConfiguration<D>::SourceAppDisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration)->get_SourceAppDisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowConfiguration<D>::JobTitle() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration)->get_JobTitle(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowConfiguration<D>::SessionId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration)->get_SessionId(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>::SetupRequested(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs> const& setupEventHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession)->add_SetupRequested(get_abi(setupEventHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>::SetupRequested_revoker consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>::SetupRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs> const& setupEventHandler) const
{
    return impl::make_event_revoker<D, SetupRequested_revoker>(this, SetupRequested(setupEventHandler));
}

template <typename D> void consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>::SetupRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession)->remove_SetupRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>::XpsDataAvailable(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs> const& xpsDataAvailableEventHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession)->add_XpsDataAvailable(get_abi(xpsDataAvailableEventHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>::XpsDataAvailable_revoker consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>::XpsDataAvailable(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs> const& xpsDataAvailableEventHandler) const
{
    return impl::make_event_revoker<D, XpsDataAvailable_revoker>(this, XpsDataAvailable(xpsDataAvailableEventHandler));
}

template <typename D> void consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>::XpsDataAvailable(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession)->remove_XpsDataAvailable(get_abi(token)));
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>::Status() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSession<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession)->Start());
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket> consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSetupRequestedEventArgs<D>::GetUserPrintTicketAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs)->GetUserPrintTicketAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSetupRequestedEventArgs<D>::Configuration() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs)->get_Configuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowForegroundSetupRequestedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket> consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSourceContent<D>::GetJobPrintTicketAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent)->GetJobPrintTicketAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSourceContent<D>::GetSourceSpoolDataAsStreamContent() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent)->GetSourceSpoolDataAsStreamContent(put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSourceContent<D>::GetSourceSpoolDataAsXpsObjectModel() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent)->GetSourceSpoolDataAsXpsObjectModel(put_abi(result)));
    return result;
}

template <typename D> Windows::Storage::Streams::IInputStream consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSpoolStreamContent<D>::GetInputStream() const
{
    Windows::Storage::Streams::IInputStream result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent)->GetInputStream(put_abi(result)));
    return result;
}

template <typename D> Windows::Storage::Streams::IOutputStream consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowStreamTarget<D>::GetOutputStream() const
{
    Windows::Storage::Streams::IOutputStream result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget)->GetOutputStream(put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedEventArgs<D>::Operation() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs)->get_Operation(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowTarget consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedEventArgs<D>::GetTarget(Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const& jobPrintTicket) const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowTarget result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs)->GetTarget(get_abi(jobPrintTicket), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedOperation<D>::Complete(Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus const& status) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation)->Complete(get_abi(status)));
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedOperation<D>::Configuration() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation)->get_Configuration(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowSubmittedOperation<D>::XpsContent() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation)->get_XpsContent(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowTarget<D>::TargetAsStream() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget)->get_TargetAsStream(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowTarget<D>::TargetAsXpsObjectModelPackage() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget)->get_TargetAsXpsObjectModelPackage(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowTriggerDetails<D>::PrintWorkflowSession() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails)->get_PrintWorkflowSession(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowUIActivatedEventArgs<D>::PrintWorkflowSession() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs)->get_PrintWorkflowSession(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowXpsDataAvailableEventArgs<D>::Operation() const
{
    Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs)->get_Operation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Graphics_Printing_Workflow_IPrintWorkflowXpsDataAvailableEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession>
{
    int32_t WINRT_CALL add_SetupRequested(void* setupEventHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetupRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SetupRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs> const*>(&setupEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SetupRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SetupRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SetupRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_Submitted(void* submittedEventHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Submitted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().Submitted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs> const*>(&submittedEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Submitted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Submitted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Submitted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Status(Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus));
            *value = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs>
{
    int32_t WINRT_CALL GetUserPrintTicketAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUserPrintTicketAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>>(this->shim().GetUserPrintTicketAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Configuration(void** configuration) noexcept final
    {
        try
        {
            *configuration = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configuration, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration));
            *configuration = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration>(this->shim().Configuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetRequiresUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetRequiresUI, WINRT_WRAP(void));
            this->shim().SetRequiresUI();
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
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration>
{
    int32_t WINRT_CALL get_SourceAppDisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceAppDisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SourceAppDisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_JobTitle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(JobTitle, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().JobTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SessionId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SessionId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SessionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession>
{
    int32_t WINRT_CALL add_SetupRequested(void* setupEventHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetupRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SetupRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs> const*>(&setupEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SetupRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SetupRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SetupRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_XpsDataAvailable(void* xpsDataAvailableEventHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XpsDataAvailable, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().XpsDataAvailable(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession, Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs> const*>(&xpsDataAvailableEventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_XpsDataAvailable(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(XpsDataAvailable, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().XpsDataAvailable(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Status(Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus));
            *value = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowSessionStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
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
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs>
{
    int32_t WINRT_CALL GetUserPrintTicketAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetUserPrintTicketAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>>(this->shim().GetUserPrintTicketAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Configuration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configuration, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration));
            *value = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration>(this->shim().Configuration());
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
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent>
{};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage>
{};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent>
{
    int32_t WINRT_CALL GetJobPrintTicketAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetJobPrintTicketAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>>(this->shim().GetJobPrintTicketAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSourceSpoolDataAsStreamContent(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSourceSpoolDataAsStreamContent, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent));
            *result = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent>(this->shim().GetSourceSpoolDataAsStreamContent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSourceSpoolDataAsXpsObjectModel(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSourceSpoolDataAsXpsObjectModel, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent));
            *result = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent>(this->shim().GetSourceSpoolDataAsXpsObjectModel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent>
{
    int32_t WINRT_CALL GetInputStream(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInputStream, WINRT_WRAP(Windows::Storage::Streams::IInputStream));
            *result = detach_from<Windows::Storage::Streams::IInputStream>(this->shim().GetInputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget>
{
    int32_t WINRT_CALL GetOutputStream(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOutputStream, WINRT_WRAP(Windows::Storage::Streams::IOutputStream));
            *result = detach_from<Windows::Storage::Streams::IOutputStream>(this->shim().GetOutputStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs>
{
    int32_t WINRT_CALL get_Operation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Operation, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation));
            *value = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation>(this->shim().Operation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTarget(void* jobPrintTicket, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTarget, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowTarget), Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const&);
            *result = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowTarget>(this->shim().GetTarget(*reinterpret_cast<Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const*>(&jobPrintTicket)));
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
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation>
{
    int32_t WINRT_CALL Complete(Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void), Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus const&);
            this->shim().Complete(*reinterpret_cast<Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedStatus const*>(&status));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Configuration(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Configuration, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration));
            *value = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration>(this->shim().Configuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_XpsContent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(XpsContent, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent));
            *value = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent>(this->shim().XpsContent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget>
{
    int32_t WINRT_CALL get_TargetAsStream(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetAsStream, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget));
            *value = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget>(this->shim().TargetAsStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetAsXpsObjectModelPackage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetAsXpsObjectModelPackage, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage));
            *value = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage>(this->shim().TargetAsXpsObjectModelPackage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails>
{
    int32_t WINRT_CALL get_PrintWorkflowSession(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintWorkflowSession, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession));
            *value = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession>(this->shim().PrintWorkflowSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs>
{
    int32_t WINRT_CALL get_PrintWorkflowSession(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintWorkflowSession, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession));
            *value = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession>(this->shim().PrintWorkflowSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs> : produce_base<D, Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs>
{
    int32_t WINRT_CALL get_Operation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Operation, WINRT_WRAP(Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation));
            *value = detach_from<Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation>(this->shim().Operation());
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

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::Workflow {

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSession> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowBackgroundSetupRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowConfiguration> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSession> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowForegroundSetupRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelSourceFileContent> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowObjectModelTargetPackage> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSourceContent> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSpoolStreamContent> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowStreamTarget> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowSubmittedOperation> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTarget> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowTriggerDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowUIActivatedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::IPrintWorkflowXpsDataAvailableEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSession> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowBackgroundSetupRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowConfiguration> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSession> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowForegroundSetupRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelSourceFileContent> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowObjectModelTargetPackage> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSourceContent> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSpoolStreamContent> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowStreamTarget> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowSubmittedOperation> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowTarget> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowTarget> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowTriggerDetails> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUIActivatedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowUIActivatedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing::Workflow::PrintWorkflowXpsDataAvailableEventArgs> {};

}
