// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.System.RemoteSystems.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.ApplicationModel.AppService.2.h"
#include "winrt/Windows.ApplicationModel.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> consume_Windows_ApplicationModel_AppService_IAppServiceCatalogStatics<D>::FindAppServiceProvidersAsync(param::hstring const& appServiceName) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceCatalogStatics)->FindAppServiceProvidersAsync(get_abi(appServiceName), put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::AppService::AppServiceClosedStatus consume_Windows_ApplicationModel_AppService_IAppServiceClosedEventArgs<D>::Status() const
{
    Windows::ApplicationModel::AppService::AppServiceClosedStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceClosedEventArgs)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::AppServiceName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection)->get_AppServiceName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::AppServiceName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection)->put_AppServiceName(get_abi(value)));
}

template <typename D> hstring consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::PackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection)->get_PackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::PackageFamilyName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection)->put_PackageFamilyName(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceConnectionStatus> consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::OpenAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceConnectionStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection)->OpenAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceResponse> consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::SendMessageAsync(Windows::Foundation::Collections::ValueSet const& message) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceResponse> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection)->SendMessageAsync(get_abi(message), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::RequestReceived(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppService::AppServiceConnection, Windows::ApplicationModel::AppService::AppServiceRequestReceivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection)->add_RequestReceived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::RequestReceived_revoker consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::RequestReceived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppService::AppServiceConnection, Windows::ApplicationModel::AppService::AppServiceRequestReceivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, RequestReceived_revoker>(this, RequestReceived(handler));
}

template <typename D> void consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::RequestReceived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection)->remove_RequestReceived(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::ServiceClosed(Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppService::AppServiceConnection, Windows::ApplicationModel::AppService::AppServiceClosedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection)->add_ServiceClosed(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::ServiceClosed_revoker consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::ServiceClosed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppService::AppServiceConnection, Windows::ApplicationModel::AppService::AppServiceClosedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ServiceClosed_revoker>(this, ServiceClosed(handler));
}

template <typename D> void consume_Windows_ApplicationModel_AppService_IAppServiceConnection<D>::ServiceClosed(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection)->remove_ServiceClosed(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceConnectionStatus> consume_Windows_ApplicationModel_AppService_IAppServiceConnection2<D>::OpenRemoteAsync(Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& remoteSystemConnectionRequest) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceConnectionStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection2)->OpenRemoteAsync(get_abi(remoteSystemConnectionRequest), put_abi(operation)));
    return operation;
}

template <typename D> Windows::System::User consume_Windows_ApplicationModel_AppService_IAppServiceConnection2<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection2)->get_User(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_AppService_IAppServiceConnection2<D>::User(Windows::System::User const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnection2)->put_User(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::StatelessAppServiceResponse> consume_Windows_ApplicationModel_AppService_IAppServiceConnectionStatics<D>::SendStatelessMessageAsync(Windows::ApplicationModel::AppService::AppServiceConnection const& connection, Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& connectionRequest, Windows::Foundation::Collections::ValueSet const& message) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::StatelessAppServiceResponse> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceConnectionStatics)->SendStatelessMessageAsync(get_abi(connection), get_abi(connectionRequest), get_abi(message), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_ApplicationModel_AppService_IAppServiceDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceDeferral)->Complete());
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_ApplicationModel_AppService_IAppServiceRequest<D>::Message() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceRequest)->get_Message(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceResponseStatus> consume_Windows_ApplicationModel_AppService_IAppServiceRequest<D>::SendResponseAsync(Windows::Foundation::Collections::ValueSet const& message) const
{
    Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceResponseStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceRequest)->SendResponseAsync(get_abi(message), put_abi(operation)));
    return operation;
}

template <typename D> Windows::ApplicationModel::AppService::AppServiceRequest consume_Windows_ApplicationModel_AppService_IAppServiceRequestReceivedEventArgs<D>::Request() const
{
    Windows::ApplicationModel::AppService::AppServiceRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceRequestReceivedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::AppService::AppServiceDeferral consume_Windows_ApplicationModel_AppService_IAppServiceRequestReceivedEventArgs<D>::GetDeferral() const
{
    Windows::ApplicationModel::AppService::AppServiceDeferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceRequestReceivedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_ApplicationModel_AppService_IAppServiceResponse<D>::Message() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceResponse)->get_Message(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::AppService::AppServiceResponseStatus consume_Windows_ApplicationModel_AppService_IAppServiceResponse<D>::Status() const
{
    Windows::ApplicationModel::AppService::AppServiceResponseStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceResponse)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceTriggerDetails)->get_Name(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails<D>::CallerPackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceTriggerDetails)->get_CallerPackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::AppService::AppServiceConnection consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails<D>::AppServiceConnection() const
{
    Windows::ApplicationModel::AppService::AppServiceConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceTriggerDetails)->get_AppServiceConnection(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails2<D>::IsRemoteSystemConnection() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceTriggerDetails2)->get_IsRemoteSystemConnection(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails3<D>::CheckCallerForCapabilityAsync(param::hstring const& capabilityName) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceTriggerDetails3)->CheckCallerForCapabilityAsync(get_abi(capabilityName), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_ApplicationModel_AppService_IAppServiceTriggerDetails4<D>::CallerRemoteConnectionToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IAppServiceTriggerDetails4)->get_CallerRemoteConnectionToken(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_ApplicationModel_AppService_IStatelessAppServiceResponse<D>::Message() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IStatelessAppServiceResponse)->get_Message(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::AppService::StatelessAppServiceResponseStatus consume_Windows_ApplicationModel_AppService_IStatelessAppServiceResponse<D>::Status() const
{
    Windows::ApplicationModel::AppService::StatelessAppServiceResponseStatus value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::AppService::IStatelessAppServiceResponse)->get_Status(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceCatalogStatics> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceCatalogStatics>
{
    int32_t WINRT_CALL FindAppServiceProvidersAsync(void* appServiceName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAppServiceProvidersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>>>(this->shim().FindAppServiceProvidersAsync(*reinterpret_cast<hstring const*>(&appServiceName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceClosedEventArgs> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceClosedEventArgs>
{
    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::AppService::AppServiceClosedStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::AppService::AppServiceClosedStatus));
            *value = detach_from<Windows::ApplicationModel::AppService::AppServiceClosedStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceConnection> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceConnection>
{
    int32_t WINRT_CALL get_AppServiceName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppServiceName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppServiceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AppServiceName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppServiceName, WINRT_WRAP(void), hstring const&);
            this->shim().AppServiceName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PackageFamilyName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PackageFamilyName, WINRT_WRAP(void), hstring const&);
            this->shim().PackageFamilyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL OpenAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceConnectionStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceConnectionStatus>>(this->shim().OpenAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendMessageAsync(void* message, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceResponse>), Windows::Foundation::Collections::ValueSet const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceResponse>>(this->shim().SendMessageAsync(*reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_RequestReceived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestReceived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppService::AppServiceConnection, Windows::ApplicationModel::AppService::AppServiceRequestReceivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().RequestReceived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppService::AppServiceConnection, Windows::ApplicationModel::AppService::AppServiceRequestReceivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_RequestReceived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(RequestReceived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().RequestReceived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ServiceClosed(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceClosed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppService::AppServiceConnection, Windows::ApplicationModel::AppService::AppServiceClosedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ServiceClosed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::ApplicationModel::AppService::AppServiceConnection, Windows::ApplicationModel::AppService::AppServiceClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ServiceClosed(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ServiceClosed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ServiceClosed(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceConnection2> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceConnection2>
{
    int32_t WINRT_CALL OpenRemoteAsync(void* remoteSystemConnectionRequest, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OpenRemoteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceConnectionStatus>), Windows::System::RemoteSystems::RemoteSystemConnectionRequest const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceConnectionStatus>>(this->shim().OpenRemoteAsync(*reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemConnectionRequest const*>(&remoteSystemConnectionRequest)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_User(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(void), Windows::System::User const&);
            this->shim().User(*reinterpret_cast<Windows::System::User const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceConnectionStatics> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceConnectionStatics>
{
    int32_t WINRT_CALL SendStatelessMessageAsync(void* connection, void* connectionRequest, void* message, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendStatelessMessageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::StatelessAppServiceResponse>), Windows::ApplicationModel::AppService::AppServiceConnection const, Windows::System::RemoteSystems::RemoteSystemConnectionRequest const, Windows::Foundation::Collections::ValueSet const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::StatelessAppServiceResponse>>(this->shim().SendStatelessMessageAsync(*reinterpret_cast<Windows::ApplicationModel::AppService::AppServiceConnection const*>(&connection), *reinterpret_cast<Windows::System::RemoteSystems::RemoteSystemConnectionRequest const*>(&connectionRequest), *reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceDeferral> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceDeferral>
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
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceRequest> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceRequest>
{
    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SendResponseAsync(void* message, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SendResponseAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceResponseStatus>), Windows::Foundation::Collections::ValueSet const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::AppServiceResponseStatus>>(this->shim().SendResponseAsync(*reinterpret_cast<Windows::Foundation::Collections::ValueSet const*>(&message)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceRequestReceivedEventArgs> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceRequestReceivedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::ApplicationModel::AppService::AppServiceRequest));
            *value = detach_from<Windows::ApplicationModel::AppService::AppServiceRequest>(this->shim().Request());
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
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::ApplicationModel::AppService::AppServiceDeferral));
            *result = detach_from<Windows::ApplicationModel::AppService::AppServiceDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceResponse> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceResponse>
{
    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::AppService::AppServiceResponseStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::AppService::AppServiceResponseStatus));
            *value = detach_from<Windows::ApplicationModel::AppService::AppServiceResponseStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceTriggerDetails> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceTriggerDetails>
{
    int32_t WINRT_CALL get_Name(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CallerPackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallerPackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CallerPackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppServiceConnection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppServiceConnection, WINRT_WRAP(Windows::ApplicationModel::AppService::AppServiceConnection));
            *value = detach_from<Windows::ApplicationModel::AppService::AppServiceConnection>(this->shim().AppServiceConnection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceTriggerDetails2> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceTriggerDetails2>
{
    int32_t WINRT_CALL get_IsRemoteSystemConnection(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRemoteSystemConnection, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRemoteSystemConnection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceTriggerDetails3> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceTriggerDetails3>
{
    int32_t WINRT_CALL CheckCallerForCapabilityAsync(void* capabilityName, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CheckCallerForCapabilityAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().CheckCallerForCapabilityAsync(*reinterpret_cast<hstring const*>(&capabilityName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IAppServiceTriggerDetails4> : produce_base<D, Windows::ApplicationModel::AppService::IAppServiceTriggerDetails4>
{
    int32_t WINRT_CALL get_CallerRemoteConnectionToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CallerRemoteConnectionToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CallerRemoteConnectionToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::AppService::IStatelessAppServiceResponse> : produce_base<D, Windows::ApplicationModel::AppService::IStatelessAppServiceResponse>
{
    int32_t WINRT_CALL get_Message(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Message, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().Message());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::ApplicationModel::AppService::StatelessAppServiceResponseStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::ApplicationModel::AppService::StatelessAppServiceResponseStatus));
            *value = detach_from<Windows::ApplicationModel::AppService::StatelessAppServiceResponseStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::AppService {

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::ApplicationModel::AppInfo>> AppServiceCatalog::FindAppServiceProvidersAsync(param::hstring const& appServiceName)
{
    return impl::call_factory<AppServiceCatalog, Windows::ApplicationModel::AppService::IAppServiceCatalogStatics>([&](auto&& f) { return f.FindAppServiceProvidersAsync(appServiceName); });
}

inline AppServiceConnection::AppServiceConnection() :
    AppServiceConnection(impl::call_factory<AppServiceConnection>([](auto&& f) { return f.template ActivateInstance<AppServiceConnection>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::ApplicationModel::AppService::StatelessAppServiceResponse> AppServiceConnection::SendStatelessMessageAsync(Windows::ApplicationModel::AppService::AppServiceConnection const& connection, Windows::System::RemoteSystems::RemoteSystemConnectionRequest const& connectionRequest, Windows::Foundation::Collections::ValueSet const& message)
{
    return impl::call_factory<AppServiceConnection, Windows::ApplicationModel::AppService::IAppServiceConnectionStatics>([&](auto&& f) { return f.SendStatelessMessageAsync(connection, connectionRequest, message); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceCatalogStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceCatalogStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceClosedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceConnection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceConnection> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceConnection2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceConnection2> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceConnectionStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceConnectionStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceRequestReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceRequestReceivedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceResponse> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceResponse> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails2> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails3> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails3> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails4> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IAppServiceTriggerDetails4> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::IStatelessAppServiceResponse> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::IStatelessAppServiceResponse> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceCatalog> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::AppServiceCatalog> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceClosedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::AppServiceClosedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceConnection> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::AppServiceConnection> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceDeferral> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::AppServiceDeferral> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceRequest> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::AppServiceRequest> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceRequestReceivedEventArgs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::AppServiceRequestReceivedEventArgs> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceResponse> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::AppServiceResponse> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::AppServiceTriggerDetails> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::AppServiceTriggerDetails> {};
template<> struct hash<winrt::Windows::ApplicationModel::AppService::StatelessAppServiceResponse> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::AppService::StatelessAppServiceResponse> {};

}
