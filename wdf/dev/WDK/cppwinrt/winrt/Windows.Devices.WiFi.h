// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Networking.Connectivity.2.h"
#include "winrt/impl/Windows.Security.Credentials.2.h"
#include "winrt/impl/Windows.Devices.WiFi.2.h"
#include "winrt/Windows.Devices.h"

namespace winrt::impl {

template <typename D> Windows::Networking::Connectivity::NetworkAdapter consume_Windows_Devices_WiFi_IWiFiAdapter<D>::NetworkAdapter() const
{
    Windows::Networking::Connectivity::NetworkAdapter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapter)->get_NetworkAdapter(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_WiFi_IWiFiAdapter<D>::ScanAsync() const
{
    Windows::Foundation::IAsyncAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapter)->ScanAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::WiFi::WiFiNetworkReport consume_Windows_Devices_WiFi_IWiFiAdapter<D>::NetworkReport() const
{
    Windows::Devices::WiFi::WiFiNetworkReport value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapter)->get_NetworkReport(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_WiFi_IWiFiAdapter<D>::AvailableNetworksChanged(Windows::Foundation::TypedEventHandler<Windows::Devices::WiFi::WiFiAdapter, Windows::Foundation::IInspectable> const& args) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapter)->add_AvailableNetworksChanged(get_abi(args), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Devices_WiFi_IWiFiAdapter<D>::AvailableNetworksChanged_revoker consume_Windows_Devices_WiFi_IWiFiAdapter<D>::AvailableNetworksChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::WiFi::WiFiAdapter, Windows::Foundation::IInspectable> const& args) const
{
    return impl::make_event_revoker<D, AvailableNetworksChanged_revoker>(this, AvailableNetworksChanged(args));
}

template <typename D> void consume_Windows_Devices_WiFi_IWiFiAdapter<D>::AvailableNetworksChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapter)->remove_AvailableNetworksChanged(get_abi(eventCookie)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult> consume_Windows_Devices_WiFi_IWiFiAdapter<D>::ConnectAsync(Windows::Devices::WiFi::WiFiAvailableNetwork const& availableNetwork, Windows::Devices::WiFi::WiFiReconnectionKind const& reconnectionKind) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapter)->ConnectAsync(get_abi(availableNetwork), get_abi(reconnectionKind), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult> consume_Windows_Devices_WiFi_IWiFiAdapter<D>::ConnectAsync(Windows::Devices::WiFi::WiFiAvailableNetwork const& availableNetwork, Windows::Devices::WiFi::WiFiReconnectionKind const& reconnectionKind, Windows::Security::Credentials::PasswordCredential const& passwordCredential) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapter)->ConnectWithPasswordCredentialAsync(get_abi(availableNetwork), get_abi(reconnectionKind), get_abi(passwordCredential), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult> consume_Windows_Devices_WiFi_IWiFiAdapter<D>::ConnectAsync(Windows::Devices::WiFi::WiFiAvailableNetwork const& availableNetwork, Windows::Devices::WiFi::WiFiReconnectionKind const& reconnectionKind, Windows::Security::Credentials::PasswordCredential const& passwordCredential, param::hstring const& ssid) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapter)->ConnectWithPasswordCredentialAndSsidAsync(get_abi(availableNetwork), get_abi(reconnectionKind), get_abi(passwordCredential), get_abi(ssid), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_WiFi_IWiFiAdapter<D>::Disconnect() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapter)->Disconnect());
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiWpsConfigurationResult> consume_Windows_Devices_WiFi_IWiFiAdapter2<D>::GetWpsConfigurationAsync(Windows::Devices::WiFi::WiFiAvailableNetwork const& availableNetwork) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiWpsConfigurationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapter2)->GetWpsConfigurationAsync(get_abi(availableNetwork), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult> consume_Windows_Devices_WiFi_IWiFiAdapter2<D>::ConnectAsync(Windows::Devices::WiFi::WiFiAvailableNetwork const& availableNetwork, Windows::Devices::WiFi::WiFiReconnectionKind const& reconnectionKind, Windows::Security::Credentials::PasswordCredential const& passwordCredential, param::hstring const& ssid, Windows::Devices::WiFi::WiFiConnectionMethod const& connectionMethod) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapter2)->ConnectWithPasswordCredentialAndSsidAndConnectionMethodAsync(get_abi(availableNetwork), get_abi(reconnectionKind), get_abi(passwordCredential), get_abi(ssid), get_abi(connectionMethod), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiAdapter>> consume_Windows_Devices_WiFi_IWiFiAdapterStatics<D>::FindAllAdaptersAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiAdapter>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapterStatics)->FindAllAdaptersAsync(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_WiFi_IWiFiAdapterStatics<D>::GetDeviceSelector() const
{
    hstring deviceSelector{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapterStatics)->GetDeviceSelector(put_abi(deviceSelector)));
    return deviceSelector;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiAdapter> consume_Windows_Devices_WiFi_IWiFiAdapterStatics<D>::FromIdAsync(param::hstring const& deviceId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiAdapter> asyncOp{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapterStatics)->FromIdAsync(get_abi(deviceId), put_abi(asyncOp)));
    return asyncOp;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiAccessStatus> consume_Windows_Devices_WiFi_IWiFiAdapterStatics<D>::RequestAccessAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiAccessStatus> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAdapterStatics)->RequestAccessAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::Uptime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_Uptime(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::Ssid() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_Ssid(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::Bssid() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_Bssid(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::ChannelCenterFrequencyInKilohertz() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_ChannelCenterFrequencyInKilohertz(&value));
    return value;
}

template <typename D> double consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::NetworkRssiInDecibelMilliwatts() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_NetworkRssiInDecibelMilliwatts(&value));
    return value;
}

template <typename D> uint8_t consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::SignalBars() const
{
    uint8_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_SignalBars(&value));
    return value;
}

template <typename D> Windows::Devices::WiFi::WiFiNetworkKind consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::NetworkKind() const
{
    Windows::Devices::WiFi::WiFiNetworkKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_NetworkKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::WiFi::WiFiPhyKind consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::PhyKind() const
{
    Windows::Devices::WiFi::WiFiPhyKind value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_PhyKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::NetworkSecuritySettings consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::SecuritySettings() const
{
    Windows::Networking::Connectivity::NetworkSecuritySettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_SecuritySettings(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::BeaconInterval() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_BeaconInterval(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_WiFi_IWiFiAvailableNetwork<D>::IsWiFiDirect() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiAvailableNetwork)->get_IsWiFiDirect(&value));
    return value;
}

template <typename D> Windows::Devices::WiFi::WiFiConnectionStatus consume_Windows_Devices_WiFi_IWiFiConnectionResult<D>::ConnectionStatus() const
{
    Windows::Devices::WiFi::WiFiConnectionStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiConnectionResult)->get_ConnectionStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Devices_WiFi_IWiFiNetworkReport<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiNetworkReport)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiAvailableNetwork> consume_Windows_Devices_WiFi_IWiFiNetworkReport<D>::AvailableNetworks() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiAvailableNetwork> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiNetworkReport)->get_AvailableNetworks(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::WiFi::WiFiWpsConfigurationStatus consume_Windows_Devices_WiFi_IWiFiWpsConfigurationResult<D>::Status() const
{
    Windows::Devices::WiFi::WiFiWpsConfigurationStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiWpsConfigurationResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiWpsKind> consume_Windows_Devices_WiFi_IWiFiWpsConfigurationResult<D>::SupportedWpsKinds() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiWpsKind> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::WiFi::IWiFiWpsConfigurationResult)->get_SupportedWpsKinds(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::WiFi::IWiFiAdapter> : produce_base<D, Windows::Devices::WiFi::IWiFiAdapter>
{
    int32_t WINRT_CALL get_NetworkAdapter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAdapter, WINRT_WRAP(Windows::Networking::Connectivity::NetworkAdapter));
            *value = detach_from<Windows::Networking::Connectivity::NetworkAdapter>(this->shim().NetworkAdapter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ScanAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScanAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *value = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ScanAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkReport(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkReport, WINRT_WRAP(Windows::Devices::WiFi::WiFiNetworkReport));
            *value = detach_from<Windows::Devices::WiFi::WiFiNetworkReport>(this->shim().NetworkReport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_AvailableNetworksChanged(void* args, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AvailableNetworksChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::WiFi::WiFiAdapter, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().AvailableNetworksChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::WiFi::WiFiAdapter, Windows::Foundation::IInspectable> const*>(&args)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AvailableNetworksChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AvailableNetworksChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AvailableNetworksChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL ConnectAsync(void* availableNetwork, Windows::Devices::WiFi::WiFiReconnectionKind reconnectionKind, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult>), Windows::Devices::WiFi::WiFiAvailableNetwork const, Windows::Devices::WiFi::WiFiReconnectionKind const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult>>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Devices::WiFi::WiFiAvailableNetwork const*>(&availableNetwork), *reinterpret_cast<Windows::Devices::WiFi::WiFiReconnectionKind const*>(&reconnectionKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectWithPasswordCredentialAsync(void* availableNetwork, Windows::Devices::WiFi::WiFiReconnectionKind reconnectionKind, void* passwordCredential, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult>), Windows::Devices::WiFi::WiFiAvailableNetwork const, Windows::Devices::WiFi::WiFiReconnectionKind const, Windows::Security::Credentials::PasswordCredential const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult>>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Devices::WiFi::WiFiAvailableNetwork const*>(&availableNetwork), *reinterpret_cast<Windows::Devices::WiFi::WiFiReconnectionKind const*>(&reconnectionKind), *reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&passwordCredential)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectWithPasswordCredentialAndSsidAsync(void* availableNetwork, Windows::Devices::WiFi::WiFiReconnectionKind reconnectionKind, void* passwordCredential, void* ssid, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult>), Windows::Devices::WiFi::WiFiAvailableNetwork const, Windows::Devices::WiFi::WiFiReconnectionKind const, Windows::Security::Credentials::PasswordCredential const, hstring const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult>>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Devices::WiFi::WiFiAvailableNetwork const*>(&availableNetwork), *reinterpret_cast<Windows::Devices::WiFi::WiFiReconnectionKind const*>(&reconnectionKind), *reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&passwordCredential), *reinterpret_cast<hstring const*>(&ssid)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Disconnect() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disconnect, WINRT_WRAP(void));
            this->shim().Disconnect();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFi::IWiFiAdapter2> : produce_base<D, Windows::Devices::WiFi::IWiFiAdapter2>
{
    int32_t WINRT_CALL GetWpsConfigurationAsync(void* availableNetwork, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetWpsConfigurationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiWpsConfigurationResult>), Windows::Devices::WiFi::WiFiAvailableNetwork const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiWpsConfigurationResult>>(this->shim().GetWpsConfigurationAsync(*reinterpret_cast<Windows::Devices::WiFi::WiFiAvailableNetwork const*>(&availableNetwork)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConnectWithPasswordCredentialAndSsidAndConnectionMethodAsync(void* availableNetwork, Windows::Devices::WiFi::WiFiReconnectionKind reconnectionKind, void* passwordCredential, void* ssid, Windows::Devices::WiFi::WiFiConnectionMethod connectionMethod, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult>), Windows::Devices::WiFi::WiFiAvailableNetwork const, Windows::Devices::WiFi::WiFiReconnectionKind const, Windows::Security::Credentials::PasswordCredential const, hstring const, Windows::Devices::WiFi::WiFiConnectionMethod const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiConnectionResult>>(this->shim().ConnectAsync(*reinterpret_cast<Windows::Devices::WiFi::WiFiAvailableNetwork const*>(&availableNetwork), *reinterpret_cast<Windows::Devices::WiFi::WiFiReconnectionKind const*>(&reconnectionKind), *reinterpret_cast<Windows::Security::Credentials::PasswordCredential const*>(&passwordCredential), *reinterpret_cast<hstring const*>(&ssid), *reinterpret_cast<Windows::Devices::WiFi::WiFiConnectionMethod const*>(&connectionMethod)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFi::IWiFiAdapterStatics> : produce_base<D, Windows::Devices::WiFi::IWiFiAdapterStatics>
{
    int32_t WINRT_CALL FindAllAdaptersAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAdaptersAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiAdapter>>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiAdapter>>>(this->shim().FindAllAdaptersAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeviceSelector(void** deviceSelector) noexcept final
    {
        try
        {
            *deviceSelector = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeviceSelector, WINRT_WRAP(hstring));
            *deviceSelector = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FromIdAsync(void* deviceId, void** asyncOp) noexcept final
    {
        try
        {
            *asyncOp = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromIdAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiAdapter>), hstring const);
            *asyncOp = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiAdapter>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAccessAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAccessAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiAccessStatus>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFi::IWiFiAvailableNetwork> : produce_base<D, Windows::Devices::WiFi::IWiFiAvailableNetwork>
{
    int32_t WINRT_CALL get_Uptime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uptime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().Uptime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ssid(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ssid, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Ssid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bssid(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bssid, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Bssid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChannelCenterFrequencyInKilohertz(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChannelCenterFrequencyInKilohertz, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ChannelCenterFrequencyInKilohertz());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkRssiInDecibelMilliwatts(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkRssiInDecibelMilliwatts, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().NetworkRssiInDecibelMilliwatts());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SignalBars(uint8_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SignalBars, WINRT_WRAP(uint8_t));
            *value = detach_from<uint8_t>(this->shim().SignalBars());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkKind(Windows::Devices::WiFi::WiFiNetworkKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkKind, WINRT_WRAP(Windows::Devices::WiFi::WiFiNetworkKind));
            *value = detach_from<Windows::Devices::WiFi::WiFiNetworkKind>(this->shim().NetworkKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhyKind(Windows::Devices::WiFi::WiFiPhyKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhyKind, WINRT_WRAP(Windows::Devices::WiFi::WiFiPhyKind));
            *value = detach_from<Windows::Devices::WiFi::WiFiPhyKind>(this->shim().PhyKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SecuritySettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SecuritySettings, WINRT_WRAP(Windows::Networking::Connectivity::NetworkSecuritySettings));
            *value = detach_from<Windows::Networking::Connectivity::NetworkSecuritySettings>(this->shim().SecuritySettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BeaconInterval(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BeaconInterval, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().BeaconInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsWiFiDirect(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWiFiDirect, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsWiFiDirect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFi::IWiFiConnectionResult> : produce_base<D, Windows::Devices::WiFi::IWiFiConnectionResult>
{
    int32_t WINRT_CALL get_ConnectionStatus(Windows::Devices::WiFi::WiFiConnectionStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionStatus, WINRT_WRAP(Windows::Devices::WiFi::WiFiConnectionStatus));
            *value = detach_from<Windows::Devices::WiFi::WiFiConnectionStatus>(this->shim().ConnectionStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFi::IWiFiNetworkReport> : produce_base<D, Windows::Devices::WiFi::IWiFiNetworkReport>
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

    int32_t WINRT_CALL get_AvailableNetworks(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AvailableNetworks, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiAvailableNetwork>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiAvailableNetwork>>(this->shim().AvailableNetworks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::WiFi::IWiFiWpsConfigurationResult> : produce_base<D, Windows::Devices::WiFi::IWiFiWpsConfigurationResult>
{
    int32_t WINRT_CALL get_Status(Windows::Devices::WiFi::WiFiWpsConfigurationStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::WiFi::WiFiWpsConfigurationStatus));
            *value = detach_from<Windows::Devices::WiFi::WiFiWpsConfigurationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedWpsKinds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedWpsKinds, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiWpsKind>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiWpsKind>>(this->shim().SupportedWpsKinds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::WiFi {

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Devices::WiFi::WiFiAdapter>> WiFiAdapter::FindAllAdaptersAsync()
{
    return impl::call_factory<WiFiAdapter, Windows::Devices::WiFi::IWiFiAdapterStatics>([&](auto&& f) { return f.FindAllAdaptersAsync(); });
}

inline hstring WiFiAdapter::GetDeviceSelector()
{
    return impl::call_factory<WiFiAdapter, Windows::Devices::WiFi::IWiFiAdapterStatics>([&](auto&& f) { return f.GetDeviceSelector(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiAdapter> WiFiAdapter::FromIdAsync(param::hstring const& deviceId)
{
    return impl::call_factory<WiFiAdapter, Windows::Devices::WiFi::IWiFiAdapterStatics>([&](auto&& f) { return f.FromIdAsync(deviceId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Devices::WiFi::WiFiAccessStatus> WiFiAdapter::RequestAccessAsync()
{
    return impl::call_factory<WiFiAdapter, Windows::Devices::WiFi::IWiFiAdapterStatics>([&](auto&& f) { return f.RequestAccessAsync(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiAdapter> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::IWiFiAdapter> {};
template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiAdapter2> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::IWiFiAdapter2> {};
template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiAdapterStatics> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::IWiFiAdapterStatics> {};
template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::IWiFiAvailableNetwork> {};
template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiConnectionResult> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::IWiFiConnectionResult> {};
template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiNetworkReport> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::IWiFiNetworkReport> {};
template<> struct hash<winrt::Windows::Devices::WiFi::IWiFiWpsConfigurationResult> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::IWiFiWpsConfigurationResult> {};
template<> struct hash<winrt::Windows::Devices::WiFi::WiFiAdapter> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::WiFiAdapter> {};
template<> struct hash<winrt::Windows::Devices::WiFi::WiFiAvailableNetwork> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::WiFiAvailableNetwork> {};
template<> struct hash<winrt::Windows::Devices::WiFi::WiFiConnectionResult> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::WiFiConnectionResult> {};
template<> struct hash<winrt::Windows::Devices::WiFi::WiFiNetworkReport> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::WiFiNetworkReport> {};
template<> struct hash<winrt::Windows::Devices::WiFi::WiFiWpsConfigurationResult> : winrt::impl::hash_base<winrt::Windows::Devices::WiFi::WiFiWpsConfigurationResult> {};

}
