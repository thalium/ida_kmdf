// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.Diagnostics.2.h"
#include "winrt/impl/Windows.Web.Http.2.h"
#include "winrt/impl/Windows.Web.Http.Diagnostics.2.h"
#include "winrt/Windows.Web.Http.h"

namespace winrt::impl {

template <typename D> void consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->Start());
}

template <typename D> void consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->Stop());
}

template <typename D> winrt::event_token consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestSent(Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->add_RequestSent(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestSent_revoker consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestSent(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RequestSent_revoker>(this, RequestSent(handler));
}

template <typename D> void consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestSent(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->remove_RequestSent(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::ResponseReceived(Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->add_ResponseReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::ResponseReceived_revoker consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::ResponseReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ResponseReceived_revoker>(this, ResponseReceived(handler));
}

template <typename D> void consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::ResponseReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->remove_ResponseReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestResponseCompleted(Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->add_RequestResponseCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestResponseCompleted_revoker consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestResponseCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RequestResponseCompleted_revoker>(this, RequestResponseCompleted(handler));
}

template <typename D> void consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>::RequestResponseCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider)->remove_RequestResponseCompleted(get_abi(token)));
}

template <typename D> winrt::guid consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::ActivityId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_ActivityId(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::Timestamps() const
{
    Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_Timestamps(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::RequestedUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_RequestedUri(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::ProcessId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_ProcessId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::ThreadId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_ThreadId(&value));
    return value;
}

template <typename D> Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::Initiator() const
{
    Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_Initiator(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation> consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>::SourceLocations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs)->get_SourceLocations(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::CacheCheckedTimestamp() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_CacheCheckedTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::ConnectionInitiatedTimestamp() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_ConnectionInitiatedTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::NameResolvedTimestamp() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_NameResolvedTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::SslNegotiatedTimestamp() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_SslNegotiatedTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::ConnectionCompletedTimestamp() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_ConnectionCompletedTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::RequestSentTimestamp() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_RequestSentTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::RequestCompletedTimestamp() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_RequestCompletedTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::ResponseReceivedTimestamp() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_ResponseReceivedTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>::ResponseCompletedTimestamp() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps)->get_ResponseCompletedTimestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::ActivityId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_ActivityId(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpRequestMessage consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::Message() const
{
    Windows::Web::Http::HttpRequestMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_Message(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::ProcessId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_ProcessId(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::ThreadId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_ThreadId(&value));
    return value;
}

template <typename D> Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::Initiator() const
{
    Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_Initiator(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation> consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>::SourceLocations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs)->get_SourceLocations(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderResponseReceivedEventArgs<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderResponseReceivedEventArgs<D>::ActivityId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs)->get_ActivityId(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::HttpResponseMessage consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderResponseReceivedEventArgs<D>::Message() const
{
    Windows::Web::Http::HttpResponseMessage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs)->get_Message(put_abi(value)));
    return value;
}

template <typename D> Windows::Web::Http::Diagnostics::HttpDiagnosticProvider consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderStatics<D>::CreateFromProcessDiagnosticInfo(Windows::System::Diagnostics::ProcessDiagnosticInfo const& processDiagnosticInfo) const
{
    Windows::Web::Http::Diagnostics::HttpDiagnosticProvider value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics)->CreateFromProcessDiagnosticInfo(get_abi(processDiagnosticInfo), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticSourceLocation<D>::SourceUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation)->get_SourceUri(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticSourceLocation<D>::LineNumber() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation)->get_LineNumber(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticSourceLocation<D>::ColumnNumber() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation)->get_ColumnNumber(&value));
    return value;
}

template <typename D>
struct produce<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider> : produce_base<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider>
{
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

    int32_t WINRT_CALL add_RequestSent(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSent, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RequestSent(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RequestSent(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RequestSent, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RequestSent(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ResponseReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ResponseReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ResponseReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ResponseReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ResponseReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_RequestResponseCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestResponseCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RequestResponseCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RequestResponseCompleted(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RequestResponseCompleted, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RequestResponseCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs> : produce_base<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs>
{
    int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivityId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Timestamps(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamps, WINRT_WRAP(Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps));
            *value = detach_from<Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps>(this->shim().Timestamps());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestedUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestedUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().RequestedUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_ThreadId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThreadId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ThreadId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Initiator(Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Initiator, WINRT_WRAP(Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator));
            *value = detach_from<Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator>(this->shim().Initiator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceLocations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceLocations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>>(this->shim().SourceLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps> : produce_base<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps>
{
    int32_t WINRT_CALL get_CacheCheckedTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CacheCheckedTimestamp, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().CacheCheckedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionInitiatedTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionInitiatedTimestamp, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ConnectionInitiatedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NameResolvedTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NameResolvedTimestamp, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().NameResolvedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SslNegotiatedTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SslNegotiatedTimestamp, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().SslNegotiatedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionCompletedTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionCompletedTimestamp, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ConnectionCompletedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestSentTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestSentTimestamp, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().RequestSentTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RequestCompletedTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestCompletedTimestamp, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().RequestCompletedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseReceivedTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseReceivedTimestamp, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ResponseReceivedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ResponseCompletedTimestamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ResponseCompletedTimestamp, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().ResponseCompletedTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs> : produce_base<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs>
{
    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivityId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(Windows::Web::Http::HttpRequestMessage));
            *value = detach_from<Windows::Web::Http::HttpRequestMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL get_ThreadId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ThreadId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().ThreadId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Initiator(Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Initiator, WINRT_WRAP(Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator));
            *value = detach_from<Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator>(this->shim().Initiator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourceLocations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceLocations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>>(this->shim().SourceLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs> : produce_base<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs>
{
    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActivityId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivityId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ActivityId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(Windows::Web::Http::HttpResponseMessage));
            *value = detach_from<Windows::Web::Http::HttpResponseMessage>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics> : produce_base<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics>
{
    int32_t WINRT_CALL CreateFromProcessDiagnosticInfo(void* processDiagnosticInfo, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromProcessDiagnosticInfo, WINRT_WRAP(Windows::Web::Http::Diagnostics::HttpDiagnosticProvider), Windows::System::Diagnostics::ProcessDiagnosticInfo const&);
            *value = detach_from<Windows::Web::Http::Diagnostics::HttpDiagnosticProvider>(this->shim().CreateFromProcessDiagnosticInfo(*reinterpret_cast<Windows::System::Diagnostics::ProcessDiagnosticInfo const*>(&processDiagnosticInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation> : produce_base<D, Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation>
{
    int32_t WINRT_CALL get_SourceUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().SourceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LineNumber(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LineNumber, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().LineNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColumnNumber(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColumnNumber, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().ColumnNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Web::Http::Diagnostics {

inline Windows::Web::Http::Diagnostics::HttpDiagnosticProvider HttpDiagnosticProvider::CreateFromProcessDiagnosticInfo(Windows::System::Diagnostics::ProcessDiagnosticInfo const& processDiagnosticInfo)
{
    return impl::call_factory<HttpDiagnosticProvider, Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics>([&](auto&& f) { return f.CreateFromProcessDiagnosticInfo(processDiagnosticInfo); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> {};
template<> struct hash<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation> : winrt::impl::hash_base<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation> {};

}
