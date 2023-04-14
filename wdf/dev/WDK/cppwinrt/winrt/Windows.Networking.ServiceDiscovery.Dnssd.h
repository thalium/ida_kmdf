// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Networking.Connectivity.2.h"
#include "winrt/impl/Windows.Networking.Sockets.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Networking.ServiceDiscovery.Dnssd.2.h"

namespace winrt::impl {

template <typename D> Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdRegistrationResult<D>::Status() const
{
    Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdRegistrationResult<D>::IPAddress() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult)->get_IPAddress(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdRegistrationResult<D>::HasInstanceNameChanged() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult)->get_HasInstanceNameChanged(&value));
    return value;
}

template <typename D> hstring consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::DnssdServiceInstanceName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_DnssdServiceInstanceName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::DnssdServiceInstanceName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->put_DnssdServiceInstanceName(get_abi(value)));
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::HostName() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_HostName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::HostName(Windows::Networking::HostName const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->put_HostName(get_abi(value)));
}

template <typename D> uint16_t consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Port() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_Port(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Port(uint16_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->put_Port(value));
}

template <typename D> uint16_t consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Priority() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_Priority(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Priority(uint16_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->put_Priority(value));
}

template <typename D> uint16_t consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Weight() const
{
    uint16_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_Weight(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::Weight(uint16_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->put_Weight(value));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::TextAttributes() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->get_TextAttributes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::RegisterStreamSocketListenerAsync(Windows::Networking::Sockets::StreamSocketListener const& socket) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->RegisterStreamSocketListenerAsync1(get_abi(socket), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::RegisterStreamSocketListenerAsync(Windows::Networking::Sockets::StreamSocketListener const& socket, Windows::Networking::Connectivity::NetworkAdapter const& adapter) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->RegisterStreamSocketListenerAsync2(get_abi(socket), get_abi(adapter), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::RegisterDatagramSocketAsync(Windows::Networking::Sockets::DatagramSocket const& socket) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->RegisterDatagramSocketAsync1(get_abi(socket), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstance<D>::RegisterDatagramSocketAsync(Windows::Networking::Sockets::DatagramSocket const& socket, Windows::Networking::Connectivity::NetworkAdapter const& adapter) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance)->RegisterDatagramSocketAsync2(get_abi(socket), get_abi(adapter), put_abi(result)));
    return result;
}

template <typename D> Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceInstanceFactory<D>::Create(param::hstring const& dnssdServiceInstanceName, Windows::Networking::HostName const& hostName, uint16_t port) const
{
    Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory)->Create(get_abi(dnssdServiceInstanceName), get_abi(hostName), port, put_abi(result)));
    return result;
}

template <typename D> winrt::event_token consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Added(Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->add_Added(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Added_revoker consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Added(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> const& handler) const
{
    return impl::make_event_revoker<D, Added_revoker>(this, Added(handler));
}

template <typename D> void consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Added(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->remove_Added(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::EnumerationCompleted(Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->add_EnumerationCompleted(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::EnumerationCompleted_revoker consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::EnumerationCompleted(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, EnumerationCompleted_revoker>(this, EnumerationCompleted(handler));
}

template <typename D> void consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::EnumerationCompleted(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->remove_EnumerationCompleted(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Stopped(Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->add_Stopped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Stopped_revoker consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Stopped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, Stopped_revoker>(this, Stopped(handler));
}

template <typename D> void consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Stopped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->remove_Stopped(get_abi(token)));
}

template <typename D> Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Status() const
{
    Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus status{};
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->get_Status(put_abi(status)));
    return status;
}

template <typename D> void consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->Start());
}

template <typename D> void consume_Windows_Networking_ServiceDiscovery_Dnssd_IDnssdServiceWatcher<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher)->Stop());
}

template <typename D>
struct produce<D, Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult> : produce_base<D, Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult>
{
    int32_t WINRT_CALL get_Status(Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus));
            *value = detach_from<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IPAddress(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IPAddress, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().IPAddress());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasInstanceNameChanged(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasInstanceNameChanged, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasInstanceNameChanged());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance> : produce_base<D, Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance>
{
    int32_t WINRT_CALL get_DnssdServiceInstanceName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DnssdServiceInstanceName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DnssdServiceInstanceName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DnssdServiceInstanceName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DnssdServiceInstanceName, WINRT_WRAP(void), hstring const&);
            this->shim().DnssdServiceInstanceName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HostName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HostName, WINRT_WRAP(Windows::Networking::HostName));
            *value = detach_from<Windows::Networking::HostName>(this->shim().HostName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HostName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HostName, WINRT_WRAP(void), Windows::Networking::HostName const&);
            this->shim().HostName(*reinterpret_cast<Windows::Networking::HostName const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Port(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Port, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Port());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Port(uint16_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Port, WINRT_WRAP(void), uint16_t);
            this->shim().Port(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Priority(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Priority, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Priority());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Priority(uint16_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Priority, WINRT_WRAP(void), uint16_t);
            this->shim().Priority(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Weight(uint16_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Weight, WINRT_WRAP(uint16_t));
            *value = detach_from<uint16_t>(this->shim().Weight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Weight(uint16_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Weight, WINRT_WRAP(void), uint16_t);
            this->shim().Weight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextAttributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextAttributes, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().TextAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterStreamSocketListenerAsync1(void* socket, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterStreamSocketListenerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>), Windows::Networking::Sockets::StreamSocketListener const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>>(this->shim().RegisterStreamSocketListenerAsync(*reinterpret_cast<Windows::Networking::Sockets::StreamSocketListener const*>(&socket)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterStreamSocketListenerAsync2(void* socket, void* adapter, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterStreamSocketListenerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>), Windows::Networking::Sockets::StreamSocketListener const, Windows::Networking::Connectivity::NetworkAdapter const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>>(this->shim().RegisterStreamSocketListenerAsync(*reinterpret_cast<Windows::Networking::Sockets::StreamSocketListener const*>(&socket), *reinterpret_cast<Windows::Networking::Connectivity::NetworkAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterDatagramSocketAsync1(void* socket, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterDatagramSocketAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>), Windows::Networking::Sockets::DatagramSocket const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>>(this->shim().RegisterDatagramSocketAsync(*reinterpret_cast<Windows::Networking::Sockets::DatagramSocket const*>(&socket)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterDatagramSocketAsync2(void* socket, void* adapter, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterDatagramSocketAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>), Windows::Networking::Sockets::DatagramSocket const, Windows::Networking::Connectivity::NetworkAdapter const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult>>(this->shim().RegisterDatagramSocketAsync(*reinterpret_cast<Windows::Networking::Sockets::DatagramSocket const*>(&socket), *reinterpret_cast<Windows::Networking::Connectivity::NetworkAdapter const*>(&adapter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory> : produce_base<D, Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory>
{
    int32_t WINRT_CALL Create(void* dnssdServiceInstanceName, void* hostName, uint16_t port, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance), hstring const&, Windows::Networking::HostName const&, uint16_t);
            *result = detach_from<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance>(this->shim().Create(*reinterpret_cast<hstring const*>(&dnssdServiceInstanceName), *reinterpret_cast<Windows::Networking::HostName const*>(&hostName), port));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher> : produce_base<D, Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher>
{
    int32_t WINRT_CALL add_Added(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Added, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> const&);
            *token = detach_from<winrt::event_token>(this->shim().Added(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> const*>(&handler)));
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

    int32_t WINRT_CALL add_EnumerationCompleted(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnumerationCompleted, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnumerationCompleted(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
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

    int32_t WINRT_CALL add_Stopped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().Stopped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Stopped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Stopped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Stopped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_Status(Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus* status) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus));
            *status = detach_from<Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcherStatus>(this->shim().Status());
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

}

WINRT_EXPORT namespace winrt::Windows::Networking::ServiceDiscovery::Dnssd {

inline DnssdRegistrationResult::DnssdRegistrationResult() :
    DnssdRegistrationResult(impl::call_factory<DnssdRegistrationResult>([](auto&& f) { return f.template ActivateInstance<DnssdRegistrationResult>(); }))
{}

inline DnssdServiceInstance::DnssdServiceInstance(param::hstring const& dnssdServiceInstanceName, Windows::Networking::HostName const& hostName, uint16_t port) :
    DnssdServiceInstance(impl::call_factory<DnssdServiceInstance, Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory>([&](auto&& f) { return f.Create(dnssdServiceInstanceName, hostName, port); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult> : winrt::impl::hash_base<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdRegistrationResult> {};
template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance> : winrt::impl::hash_base<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstance> {};
template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory> : winrt::impl::hash_base<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceInstanceFactory> {};
template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher> : winrt::impl::hash_base<winrt::Windows::Networking::ServiceDiscovery::Dnssd::IDnssdServiceWatcher> {};
template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> : winrt::impl::hash_base<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdRegistrationResult> {};
template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> : winrt::impl::hash_base<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstance> {};
template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstanceCollection> : winrt::impl::hash_base<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceInstanceCollection> {};
template<> struct hash<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher> : winrt::impl::hash_base<winrt::Windows::Networking::ServiceDiscovery::Dnssd::DnssdServiceWatcher> {};

}
