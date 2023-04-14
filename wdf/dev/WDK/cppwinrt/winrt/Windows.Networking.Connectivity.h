// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Networking.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Networking.Connectivity.2.h"
#include "winrt/Windows.Networking.h"

namespace winrt::impl {

template <typename D> uint64_t consume_Windows_Networking_Connectivity_IAttributedNetworkUsage<D>::BytesSent() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IAttributedNetworkUsage)->get_BytesSent(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Networking_Connectivity_IAttributedNetworkUsage<D>::BytesReceived() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IAttributedNetworkUsage)->get_BytesReceived(&value));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Connectivity_IAttributedNetworkUsage<D>::AttributionId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IAttributedNetworkUsage)->get_AttributionId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Connectivity_IAttributedNetworkUsage<D>::AttributionName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IAttributedNetworkUsage)->get_AttributionName(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_Networking_Connectivity_IAttributedNetworkUsage<D>::AttributionThumbnail() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IAttributedNetworkUsage)->get_AttributionThumbnail(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Connectivity_ICellularApnContext<D>::ProviderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->get_ProviderId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_ICellularApnContext<D>::ProviderId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->put_ProviderId(get_abi(value)));
}

template <typename D> hstring consume_Windows_Networking_Connectivity_ICellularApnContext<D>::AccessPointName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->get_AccessPointName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_ICellularApnContext<D>::AccessPointName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->put_AccessPointName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Networking_Connectivity_ICellularApnContext<D>::UserName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->get_UserName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_ICellularApnContext<D>::UserName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->put_UserName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Networking_Connectivity_ICellularApnContext<D>::Password() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->get_Password(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_ICellularApnContext<D>::Password(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->put_Password(get_abi(value)));
}

template <typename D> bool consume_Windows_Networking_Connectivity_ICellularApnContext<D>::IsCompressionEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->get_IsCompressionEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_ICellularApnContext<D>::IsCompressionEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->put_IsCompressionEnabled(value));
}

template <typename D> Windows::Networking::Connectivity::CellularApnAuthenticationType consume_Windows_Networking_Connectivity_ICellularApnContext<D>::AuthenticationType() const
{
    Windows::Networking::Connectivity::CellularApnAuthenticationType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->get_AuthenticationType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_ICellularApnContext<D>::AuthenticationType(Windows::Networking::Connectivity::CellularApnAuthenticationType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext)->put_AuthenticationType(get_abi(value)));
}

template <typename D> hstring consume_Windows_Networking_Connectivity_ICellularApnContext2<D>::ProfileName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext2)->get_ProfileName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_ICellularApnContext2<D>::ProfileName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ICellularApnContext2)->put_ProfileName(get_abi(value)));
}

template <typename D> Windows::Networking::Connectivity::NetworkCostType consume_Windows_Networking_Connectivity_IConnectionCost<D>::NetworkCostType() const
{
    Windows::Networking::Connectivity::NetworkCostType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionCost)->get_NetworkCostType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_IConnectionCost<D>::Roaming() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionCost)->get_Roaming(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_IConnectionCost<D>::OverDataLimit() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionCost)->get_OverDataLimit(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_IConnectionCost<D>::ApproachingDataLimit() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionCost)->get_ApproachingDataLimit(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_IConnectionCost2<D>::BackgroundDataUsageRestricted() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionCost2)->get_BackgroundDataUsageRestricted(&value));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Connectivity_IConnectionProfile<D>::ProfileName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile)->get_ProfileName(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::NetworkConnectivityLevel consume_Windows_Networking_Connectivity_IConnectionProfile<D>::GetNetworkConnectivityLevel() const
{
    Windows::Networking::Connectivity::NetworkConnectivityLevel value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile)->GetNetworkConnectivityLevel(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Networking_Connectivity_IConnectionProfile<D>::GetNetworkNames() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile)->GetNetworkNames(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::ConnectionCost consume_Windows_Networking_Connectivity_IConnectionProfile<D>::GetConnectionCost() const
{
    Windows::Networking::Connectivity::ConnectionCost value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile)->GetConnectionCost(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::DataPlanStatus consume_Windows_Networking_Connectivity_IConnectionProfile<D>::GetDataPlanStatus() const
{
    Windows::Networking::Connectivity::DataPlanStatus value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile)->GetDataPlanStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::NetworkAdapter consume_Windows_Networking_Connectivity_IConnectionProfile<D>::NetworkAdapter() const
{
    Windows::Networking::Connectivity::NetworkAdapter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile)->get_NetworkAdapter(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::DataUsage consume_Windows_Networking_Connectivity_IConnectionProfile<D>::GetLocalUsage(Windows::Foundation::DateTime const& StartTime, Windows::Foundation::DateTime const& EndTime) const
{
    Windows::Networking::Connectivity::DataUsage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile)->GetLocalUsage(get_abi(StartTime), get_abi(EndTime), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::DataUsage consume_Windows_Networking_Connectivity_IConnectionProfile<D>::GetLocalUsage(Windows::Foundation::DateTime const& StartTime, Windows::Foundation::DateTime const& EndTime, Windows::Networking::Connectivity::RoamingStates const& States) const
{
    Windows::Networking::Connectivity::DataUsage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile)->GetLocalUsagePerRoamingStates(get_abi(StartTime), get_abi(EndTime), get_abi(States), put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::NetworkSecuritySettings consume_Windows_Networking_Connectivity_IConnectionProfile<D>::NetworkSecuritySettings() const
{
    Windows::Networking::Connectivity::NetworkSecuritySettings value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile)->get_NetworkSecuritySettings(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_IConnectionProfile2<D>::IsWwanConnectionProfile() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile2)->get_IsWwanConnectionProfile(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_IConnectionProfile2<D>::IsWlanConnectionProfile() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile2)->get_IsWlanConnectionProfile(&value));
    return value;
}

template <typename D> Windows::Networking::Connectivity::WwanConnectionProfileDetails consume_Windows_Networking_Connectivity_IConnectionProfile2<D>::WwanConnectionProfileDetails() const
{
    Windows::Networking::Connectivity::WwanConnectionProfileDetails value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile2)->get_WwanConnectionProfileDetails(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::WlanConnectionProfileDetails consume_Windows_Networking_Connectivity_IConnectionProfile2<D>::WlanConnectionProfileDetails() const
{
    Windows::Networking::Connectivity::WlanConnectionProfileDetails value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile2)->get_WlanConnectionProfileDetails(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<winrt::guid> consume_Windows_Networking_Connectivity_IConnectionProfile2<D>::ServiceProviderGuid() const
{
    Windows::Foundation::IReference<winrt::guid> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile2)->get_ServiceProviderGuid(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint8_t> consume_Windows_Networking_Connectivity_IConnectionProfile2<D>::GetSignalBars() const
{
    Windows::Foundation::IReference<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile2)->GetSignalBars(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::DomainConnectivityLevel consume_Windows_Networking_Connectivity_IConnectionProfile2<D>::GetDomainConnectivityLevel() const
{
    Windows::Networking::Connectivity::DomainConnectivityLevel value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile2)->GetDomainConnectivityLevel(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::NetworkUsage>> consume_Windows_Networking_Connectivity_IConnectionProfile2<D>::GetNetworkUsageAsync(Windows::Foundation::DateTime const& startTime, Windows::Foundation::DateTime const& endTime, Windows::Networking::Connectivity::DataUsageGranularity const& granularity, Windows::Networking::Connectivity::NetworkUsageStates const& states) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::NetworkUsage>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile2)->GetNetworkUsageAsync(get_abi(startTime), get_abi(endTime), get_abi(granularity), get_abi(states), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectivityInterval>> consume_Windows_Networking_Connectivity_IConnectionProfile2<D>::GetConnectivityIntervalsAsync(Windows::Foundation::DateTime const& startTime, Windows::Foundation::DateTime const& endTime, Windows::Networking::Connectivity::NetworkUsageStates const& states) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectivityInterval>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile2)->GetConnectivityIntervalsAsync(get_abi(startTime), get_abi(endTime), get_abi(states), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::AttributedNetworkUsage>> consume_Windows_Networking_Connectivity_IConnectionProfile3<D>::GetAttributedNetworkUsageAsync(Windows::Foundation::DateTime const& startTime, Windows::Foundation::DateTime const& endTime, Windows::Networking::Connectivity::NetworkUsageStates const& states) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::AttributedNetworkUsage>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile3)->GetAttributedNetworkUsageAsync(get_abi(startTime), get_abi(endTime), get_abi(states), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ProviderNetworkUsage>> consume_Windows_Networking_Connectivity_IConnectionProfile4<D>::GetProviderNetworkUsageAsync(Windows::Foundation::DateTime const& startTime, Windows::Foundation::DateTime const& endTime, Windows::Networking::Connectivity::NetworkUsageStates const& states) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ProviderNetworkUsage>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile4)->GetProviderNetworkUsageAsync(get_abi(startTime), get_abi(endTime), get_abi(states), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_IConnectionProfile5<D>::CanDelete() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile5)->get_CanDelete(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionProfileDeleteStatus> consume_Windows_Networking_Connectivity_IConnectionProfile5<D>::TryDeleteAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionProfileDeleteStatus> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfile5)->TryDeleteAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Networking_Connectivity_IConnectionProfileFilter<D>::IsConnected(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter)->put_IsConnected(value));
}

template <typename D> bool consume_Windows_Networking_Connectivity_IConnectionProfileFilter<D>::IsConnected() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter)->get_IsConnected(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_IConnectionProfileFilter<D>::IsWwanConnectionProfile(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter)->put_IsWwanConnectionProfile(value));
}

template <typename D> bool consume_Windows_Networking_Connectivity_IConnectionProfileFilter<D>::IsWwanConnectionProfile() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter)->get_IsWwanConnectionProfile(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_IConnectionProfileFilter<D>::IsWlanConnectionProfile(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter)->put_IsWlanConnectionProfile(value));
}

template <typename D> bool consume_Windows_Networking_Connectivity_IConnectionProfileFilter<D>::IsWlanConnectionProfile() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter)->get_IsWlanConnectionProfile(&value));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_IConnectionProfileFilter<D>::NetworkCostType(Windows::Networking::Connectivity::NetworkCostType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter)->put_NetworkCostType(get_abi(value)));
}

template <typename D> Windows::Networking::Connectivity::NetworkCostType consume_Windows_Networking_Connectivity_IConnectionProfileFilter<D>::NetworkCostType() const
{
    Windows::Networking::Connectivity::NetworkCostType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter)->get_NetworkCostType(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_IConnectionProfileFilter<D>::ServiceProviderGuid(optional<winrt::guid> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter)->put_ServiceProviderGuid(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<winrt::guid> consume_Windows_Networking_Connectivity_IConnectionProfileFilter<D>::ServiceProviderGuid() const
{
    Windows::Foundation::IReference<winrt::guid> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter)->get_ServiceProviderGuid(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_IConnectionProfileFilter2<D>::IsRoaming(optional<bool> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter2)->put_IsRoaming(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<bool> consume_Windows_Networking_Connectivity_IConnectionProfileFilter2<D>::IsRoaming() const
{
    Windows::Foundation::IReference<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter2)->get_IsRoaming(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_IConnectionProfileFilter2<D>::IsOverDataLimit(optional<bool> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter2)->put_IsOverDataLimit(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<bool> consume_Windows_Networking_Connectivity_IConnectionProfileFilter2<D>::IsOverDataLimit() const
{
    Windows::Foundation::IReference<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter2)->get_IsOverDataLimit(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_IConnectionProfileFilter2<D>::IsBackgroundDataUsageRestricted(optional<bool> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter2)->put_IsBackgroundDataUsageRestricted(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<bool> consume_Windows_Networking_Connectivity_IConnectionProfileFilter2<D>::IsBackgroundDataUsageRestricted() const
{
    Windows::Foundation::IReference<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter2)->get_IsBackgroundDataUsageRestricted(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Networking_Connectivity_IConnectionProfileFilter2<D>::RawData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter2)->get_RawData(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Networking_Connectivity_IConnectionProfileFilter3<D>::PurposeGuid(optional<winrt::guid> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter3)->put_PurposeGuid(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<winrt::guid> consume_Windows_Networking_Connectivity_IConnectionProfileFilter3<D>::PurposeGuid() const
{
    Windows::Foundation::IReference<winrt::guid> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionProfileFilter3)->get_PurposeGuid(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::ConnectionProfile consume_Windows_Networking_Connectivity_IConnectionSession<D>::ConnectionProfile() const
{
    Windows::Networking::Connectivity::ConnectionProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectionSession)->get_ConnectionProfile(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Networking_Connectivity_IConnectivityInterval<D>::StartTime() const
{
    Windows::Foundation::DateTime startTime{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectivityInterval)->get_StartTime(put_abi(startTime)));
    return startTime;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Networking_Connectivity_IConnectivityInterval<D>::ConnectionDuration() const
{
    Windows::Foundation::TimeSpan duration{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectivityInterval)->get_ConnectionDuration(put_abi(duration)));
    return duration;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionSession> consume_Windows_Networking_Connectivity_IConnectivityManagerStatics<D>::AcquireConnectionAsync(Windows::Networking::Connectivity::CellularApnContext const& cellularApnContext) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionSession> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectivityManagerStatics)->AcquireConnectionAsync(get_abi(cellularApnContext), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Networking_Connectivity_IConnectivityManagerStatics<D>::AddHttpRoutePolicy(Windows::Networking::Connectivity::RoutePolicy const& routePolicy) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectivityManagerStatics)->AddHttpRoutePolicy(get_abi(routePolicy)));
}

template <typename D> void consume_Windows_Networking_Connectivity_IConnectivityManagerStatics<D>::RemoveHttpRoutePolicy(Windows::Networking::Connectivity::RoutePolicy const& routePolicy) const
{
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IConnectivityManagerStatics)->RemoveHttpRoutePolicy(get_abi(routePolicy)));
}

template <typename D> Windows::Networking::Connectivity::DataPlanUsage consume_Windows_Networking_Connectivity_IDataPlanStatus<D>::DataPlanUsage() const
{
    Windows::Networking::Connectivity::DataPlanUsage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IDataPlanStatus)->get_DataPlanUsage(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Networking_Connectivity_IDataPlanStatus<D>::DataLimitInMegabytes() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IDataPlanStatus)->get_DataLimitInMegabytes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Networking_Connectivity_IDataPlanStatus<D>::InboundBitsPerSecond() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IDataPlanStatus)->get_InboundBitsPerSecond(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint64_t> consume_Windows_Networking_Connectivity_IDataPlanStatus<D>::OutboundBitsPerSecond() const
{
    Windows::Foundation::IReference<uint64_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IDataPlanStatus)->get_OutboundBitsPerSecond(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_Networking_Connectivity_IDataPlanStatus<D>::NextBillingCycle() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IDataPlanStatus)->get_NextBillingCycle(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint32_t> consume_Windows_Networking_Connectivity_IDataPlanStatus<D>::MaxTransferSizeInMegabytes() const
{
    Windows::Foundation::IReference<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IDataPlanStatus)->get_MaxTransferSizeInMegabytes(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_Connectivity_IDataPlanUsage<D>::MegabytesUsed() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IDataPlanUsage)->get_MegabytesUsed(&value));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Networking_Connectivity_IDataPlanUsage<D>::LastSyncTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IDataPlanUsage)->get_LastSyncTime(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Networking_Connectivity_IDataUsage<D>::BytesSent() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IDataUsage)->get_BytesSent(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Networking_Connectivity_IDataUsage<D>::BytesReceived() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IDataUsage)->get_BytesReceived(&value));
    return value;
}

template <typename D> Windows::Networking::Connectivity::NetworkAdapter consume_Windows_Networking_Connectivity_IIPInformation<D>::NetworkAdapter() const
{
    Windows::Networking::Connectivity::NetworkAdapter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IIPInformation)->get_NetworkAdapter(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<uint8_t> consume_Windows_Networking_Connectivity_IIPInformation<D>::PrefixLength() const
{
    Windows::Foundation::IReference<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IIPInformation)->get_PrefixLength(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::LanIdentifierData consume_Windows_Networking_Connectivity_ILanIdentifier<D>::InfrastructureId() const
{
    Windows::Networking::Connectivity::LanIdentifierData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ILanIdentifier)->get_InfrastructureId(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::LanIdentifierData consume_Windows_Networking_Connectivity_ILanIdentifier<D>::PortId() const
{
    Windows::Networking::Connectivity::LanIdentifierData value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ILanIdentifier)->get_PortId(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Networking_Connectivity_ILanIdentifier<D>::NetworkAdapterId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ILanIdentifier)->get_NetworkAdapterId(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_Connectivity_ILanIdentifierData<D>::Type() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ILanIdentifierData)->get_Type(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint8_t> consume_Windows_Networking_Connectivity_ILanIdentifierData<D>::Value() const
{
    Windows::Foundation::Collections::IVectorView<uint8_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::ILanIdentifierData)->get_Value(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Networking_Connectivity_INetworkAdapter<D>::OutboundMaxBitsPerSecond() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkAdapter)->get_OutboundMaxBitsPerSecond(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Networking_Connectivity_INetworkAdapter<D>::InboundMaxBitsPerSecond() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkAdapter)->get_InboundMaxBitsPerSecond(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Networking_Connectivity_INetworkAdapter<D>::IanaInterfaceType() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkAdapter)->get_IanaInterfaceType(&value));
    return value;
}

template <typename D> Windows::Networking::Connectivity::NetworkItem consume_Windows_Networking_Connectivity_INetworkAdapter<D>::NetworkItem() const
{
    Windows::Networking::Connectivity::NetworkItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkAdapter)->get_NetworkItem(put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Networking_Connectivity_INetworkAdapter<D>::NetworkAdapterId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkAdapter)->get_NetworkAdapterId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionProfile> consume_Windows_Networking_Connectivity_INetworkAdapter<D>::GetConnectedProfileAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionProfile> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkAdapter)->GetConnectedProfileAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile> consume_Windows_Networking_Connectivity_INetworkInformationStatics<D>::GetConnectionProfiles() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkInformationStatics)->GetConnectionProfiles(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::ConnectionProfile consume_Windows_Networking_Connectivity_INetworkInformationStatics<D>::GetInternetConnectionProfile() const
{
    Windows::Networking::Connectivity::ConnectionProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkInformationStatics)->GetInternetConnectionProfile(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::LanIdentifier> consume_Windows_Networking_Connectivity_INetworkInformationStatics<D>::GetLanIdentifiers() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::LanIdentifier> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkInformationStatics)->GetLanIdentifiers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName> consume_Windows_Networking_Connectivity_INetworkInformationStatics<D>::GetHostNames() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkInformationStatics)->GetHostNames(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ProxyConfiguration> consume_Windows_Networking_Connectivity_INetworkInformationStatics<D>::GetProxyConfigurationAsync(Windows::Foundation::Uri const& uri) const
{
    Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ProxyConfiguration> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkInformationStatics)->GetProxyConfigurationAsync(get_abi(uri), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair> consume_Windows_Networking_Connectivity_INetworkInformationStatics<D>::GetSortedEndpointPairs(param::iterable<Windows::Networking::EndpointPair> const& destinationList, Windows::Networking::HostNameSortOptions const& sortOptions) const
{
    Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkInformationStatics)->GetSortedEndpointPairs(get_abi(destinationList), get_abi(sortOptions), put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Networking_Connectivity_INetworkInformationStatics<D>::NetworkStatusChanged(Windows::Networking::Connectivity::NetworkStatusChangedEventHandler const& networkStatusHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkInformationStatics)->add_NetworkStatusChanged(get_abi(networkStatusHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Networking_Connectivity_INetworkInformationStatics<D>::NetworkStatusChanged_revoker consume_Windows_Networking_Connectivity_INetworkInformationStatics<D>::NetworkStatusChanged(auto_revoke_t, Windows::Networking::Connectivity::NetworkStatusChangedEventHandler const& networkStatusHandler) const
{
    return impl::make_event_revoker<D, NetworkStatusChanged_revoker>(this, NetworkStatusChanged(networkStatusHandler));
}

template <typename D> void consume_Windows_Networking_Connectivity_INetworkInformationStatics<D>::NetworkStatusChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Networking::Connectivity::INetworkInformationStatics)->remove_NetworkStatusChanged(get_abi(eventCookie)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile>> consume_Windows_Networking_Connectivity_INetworkInformationStatics2<D>::FindConnectionProfilesAsync(Windows::Networking::Connectivity::ConnectionProfileFilter const& pProfileFilter) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile>> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkInformationStatics2)->FindConnectionProfilesAsync(get_abi(pProfileFilter), put_abi(value)));
    return value;
}

template <typename D> winrt::guid consume_Windows_Networking_Connectivity_INetworkItem<D>::NetworkId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkItem)->get_NetworkId(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::NetworkTypes consume_Windows_Networking_Connectivity_INetworkItem<D>::GetNetworkTypes() const
{
    Windows::Networking::Connectivity::NetworkTypes value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkItem)->GetNetworkTypes(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::NetworkAuthenticationType consume_Windows_Networking_Connectivity_INetworkSecuritySettings<D>::NetworkAuthenticationType() const
{
    Windows::Networking::Connectivity::NetworkAuthenticationType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkSecuritySettings)->get_NetworkAuthenticationType(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::NetworkEncryptionType consume_Windows_Networking_Connectivity_INetworkSecuritySettings<D>::NetworkEncryptionType() const
{
    Windows::Networking::Connectivity::NetworkEncryptionType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkSecuritySettings)->get_NetworkEncryptionType(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_INetworkStateChangeEventDetails<D>::HasNewInternetConnectionProfile() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkStateChangeEventDetails)->get_HasNewInternetConnectionProfile(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_INetworkStateChangeEventDetails<D>::HasNewConnectionCost() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkStateChangeEventDetails)->get_HasNewConnectionCost(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_INetworkStateChangeEventDetails<D>::HasNewNetworkConnectivityLevel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkStateChangeEventDetails)->get_HasNewNetworkConnectivityLevel(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_INetworkStateChangeEventDetails<D>::HasNewDomainConnectivityLevel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkStateChangeEventDetails)->get_HasNewDomainConnectivityLevel(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_INetworkStateChangeEventDetails<D>::HasNewHostNameList() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkStateChangeEventDetails)->get_HasNewHostNameList(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_INetworkStateChangeEventDetails<D>::HasNewWwanRegistrationState() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkStateChangeEventDetails)->get_HasNewWwanRegistrationState(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_INetworkStateChangeEventDetails2<D>::HasNewTetheringOperationalState() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkStateChangeEventDetails2)->get_HasNewTetheringOperationalState(&value));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_INetworkStateChangeEventDetails2<D>::HasNewTetheringClientCount() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkStateChangeEventDetails2)->get_HasNewTetheringClientCount(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Networking_Connectivity_INetworkUsage<D>::BytesSent() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkUsage)->get_BytesSent(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Networking_Connectivity_INetworkUsage<D>::BytesReceived() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkUsage)->get_BytesReceived(&value));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Networking_Connectivity_INetworkUsage<D>::ConnectionDuration() const
{
    Windows::Foundation::TimeSpan duration{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::INetworkUsage)->get_ConnectionDuration(put_abi(duration)));
    return duration;
}

template <typename D> uint64_t consume_Windows_Networking_Connectivity_IProviderNetworkUsage<D>::BytesSent() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IProviderNetworkUsage)->get_BytesSent(&value));
    return value;
}

template <typename D> uint64_t consume_Windows_Networking_Connectivity_IProviderNetworkUsage<D>::BytesReceived() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IProviderNetworkUsage)->get_BytesReceived(&value));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Connectivity_IProviderNetworkUsage<D>::ProviderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IProviderNetworkUsage)->get_ProviderId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Foundation::Uri> consume_Windows_Networking_Connectivity_IProxyConfiguration<D>::ProxyUris() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Foundation::Uri> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IProxyConfiguration)->get_ProxyUris(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Networking_Connectivity_IProxyConfiguration<D>::CanConnectDirectly() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IProxyConfiguration)->get_CanConnectDirectly(&value));
    return value;
}

template <typename D> Windows::Networking::Connectivity::ConnectionProfile consume_Windows_Networking_Connectivity_IRoutePolicy<D>::ConnectionProfile() const
{
    Windows::Networking::Connectivity::ConnectionProfile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IRoutePolicy)->get_ConnectionProfile(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::HostName consume_Windows_Networking_Connectivity_IRoutePolicy<D>::HostName() const
{
    Windows::Networking::HostName value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IRoutePolicy)->get_HostName(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::DomainNameType consume_Windows_Networking_Connectivity_IRoutePolicy<D>::HostNameType() const
{
    Windows::Networking::DomainNameType value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IRoutePolicy)->get_HostNameType(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::RoutePolicy consume_Windows_Networking_Connectivity_IRoutePolicyFactory<D>::CreateRoutePolicy(Windows::Networking::Connectivity::ConnectionProfile const& connectionProfile, Windows::Networking::HostName const& hostName, Windows::Networking::DomainNameType const& type) const
{
    Windows::Networking::Connectivity::RoutePolicy routePolicy{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IRoutePolicyFactory)->CreateRoutePolicy(get_abi(connectionProfile), get_abi(hostName), get_abi(type), put_abi(routePolicy)));
    return routePolicy;
}

template <typename D> hstring consume_Windows_Networking_Connectivity_IWlanConnectionProfileDetails<D>::GetConnectedSsid() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IWlanConnectionProfileDetails)->GetConnectedSsid(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Connectivity_IWwanConnectionProfileDetails<D>::HomeProviderId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IWwanConnectionProfileDetails)->get_HomeProviderId(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Networking_Connectivity_IWwanConnectionProfileDetails<D>::AccessPointName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IWwanConnectionProfileDetails)->get_AccessPointName(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::WwanNetworkRegistrationState consume_Windows_Networking_Connectivity_IWwanConnectionProfileDetails<D>::GetNetworkRegistrationState() const
{
    Windows::Networking::Connectivity::WwanNetworkRegistrationState value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IWwanConnectionProfileDetails)->GetNetworkRegistrationState(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::WwanDataClass consume_Windows_Networking_Connectivity_IWwanConnectionProfileDetails<D>::GetCurrentDataClass() const
{
    Windows::Networking::Connectivity::WwanDataClass value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IWwanConnectionProfileDetails)->GetCurrentDataClass(put_abi(value)));
    return value;
}

template <typename D> Windows::Networking::Connectivity::WwanNetworkIPKind consume_Windows_Networking_Connectivity_IWwanConnectionProfileDetails2<D>::IPKind() const
{
    Windows::Networking::Connectivity::WwanNetworkIPKind value{};
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IWwanConnectionProfileDetails2)->get_IPKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<winrt::guid> consume_Windows_Networking_Connectivity_IWwanConnectionProfileDetails2<D>::PurposeGuids() const
{
    Windows::Foundation::Collections::IVectorView<winrt::guid> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Networking::Connectivity::IWwanConnectionProfileDetails2)->get_PurposeGuids(put_abi(value)));
    return value;
}

template <> struct delegate<Windows::Networking::Connectivity::NetworkStatusChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Networking::Connectivity::NetworkStatusChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Networking::Connectivity::NetworkStatusChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IAttributedNetworkUsage> : produce_base<D, Windows::Networking::Connectivity::IAttributedNetworkUsage>
{
    int32_t WINRT_CALL get_BytesSent(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesSent, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BytesSent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BytesReceived(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesReceived, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BytesReceived());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttributionId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttributionId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AttributionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttributionName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttributionName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AttributionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AttributionThumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AttributionThumbnail, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().AttributionThumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::ICellularApnContext> : produce_base<D, Windows::Networking::Connectivity::ICellularApnContext>
{
    int32_t WINRT_CALL get_ProviderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProviderId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderId, WINRT_WRAP(void), hstring const&);
            this->shim().ProviderId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessPointName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessPointName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AccessPointName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AccessPointName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessPointName, WINRT_WRAP(void), hstring const&);
            this->shim().AccessPointName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UserName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UserName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserName, WINRT_WRAP(void), hstring const&);
            this->shim().UserName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Password(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Password, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Password());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Password(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Password, WINRT_WRAP(void), hstring const&);
            this->shim().Password(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCompressionEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCompressionEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCompressionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCompressionEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCompressionEnabled, WINRT_WRAP(void), bool);
            this->shim().IsCompressionEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AuthenticationType(Windows::Networking::Connectivity::CellularApnAuthenticationType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationType, WINRT_WRAP(Windows::Networking::Connectivity::CellularApnAuthenticationType));
            *value = detach_from<Windows::Networking::Connectivity::CellularApnAuthenticationType>(this->shim().AuthenticationType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AuthenticationType(Windows::Networking::Connectivity::CellularApnAuthenticationType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AuthenticationType, WINRT_WRAP(void), Windows::Networking::Connectivity::CellularApnAuthenticationType const&);
            this->shim().AuthenticationType(*reinterpret_cast<Windows::Networking::Connectivity::CellularApnAuthenticationType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::ICellularApnContext2> : produce_base<D, Windows::Networking::Connectivity::ICellularApnContext2>
{
    int32_t WINRT_CALL get_ProfileName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProfileName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProfileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProfileName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProfileName, WINRT_WRAP(void), hstring const&);
            this->shim().ProfileName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectionCost> : produce_base<D, Windows::Networking::Connectivity::IConnectionCost>
{
    int32_t WINRT_CALL get_NetworkCostType(Windows::Networking::Connectivity::NetworkCostType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkCostType, WINRT_WRAP(Windows::Networking::Connectivity::NetworkCostType));
            *value = detach_from<Windows::Networking::Connectivity::NetworkCostType>(this->shim().NetworkCostType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Roaming(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Roaming, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Roaming());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OverDataLimit(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverDataLimit, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().OverDataLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ApproachingDataLimit(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ApproachingDataLimit, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ApproachingDataLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectionCost2> : produce_base<D, Windows::Networking::Connectivity::IConnectionCost2>
{
    int32_t WINRT_CALL get_BackgroundDataUsageRestricted(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundDataUsageRestricted, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().BackgroundDataUsageRestricted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectionProfile> : produce_base<D, Windows::Networking::Connectivity::IConnectionProfile>
{
    int32_t WINRT_CALL get_ProfileName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProfileName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProfileName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNetworkConnectivityLevel(Windows::Networking::Connectivity::NetworkConnectivityLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNetworkConnectivityLevel, WINRT_WRAP(Windows::Networking::Connectivity::NetworkConnectivityLevel));
            *value = detach_from<Windows::Networking::Connectivity::NetworkConnectivityLevel>(this->shim().GetNetworkConnectivityLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNetworkNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNetworkNames, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().GetNetworkNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConnectionCost(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConnectionCost, WINRT_WRAP(Windows::Networking::Connectivity::ConnectionCost));
            *value = detach_from<Windows::Networking::Connectivity::ConnectionCost>(this->shim().GetConnectionCost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDataPlanStatus(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDataPlanStatus, WINRT_WRAP(Windows::Networking::Connectivity::DataPlanStatus));
            *value = detach_from<Windows::Networking::Connectivity::DataPlanStatus>(this->shim().GetDataPlanStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL GetLocalUsage(Windows::Foundation::DateTime StartTime, Windows::Foundation::DateTime EndTime, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocalUsage, WINRT_WRAP(Windows::Networking::Connectivity::DataUsage), Windows::Foundation::DateTime const&, Windows::Foundation::DateTime const&);
            *value = detach_from<Windows::Networking::Connectivity::DataUsage>(this->shim().GetLocalUsage(*reinterpret_cast<Windows::Foundation::DateTime const*>(&StartTime), *reinterpret_cast<Windows::Foundation::DateTime const*>(&EndTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocalUsagePerRoamingStates(Windows::Foundation::DateTime StartTime, Windows::Foundation::DateTime EndTime, Windows::Networking::Connectivity::RoamingStates States, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocalUsage, WINRT_WRAP(Windows::Networking::Connectivity::DataUsage), Windows::Foundation::DateTime const&, Windows::Foundation::DateTime const&, Windows::Networking::Connectivity::RoamingStates const&);
            *value = detach_from<Windows::Networking::Connectivity::DataUsage>(this->shim().GetLocalUsage(*reinterpret_cast<Windows::Foundation::DateTime const*>(&StartTime), *reinterpret_cast<Windows::Foundation::DateTime const*>(&EndTime), *reinterpret_cast<Windows::Networking::Connectivity::RoamingStates const*>(&States)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkSecuritySettings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkSecuritySettings, WINRT_WRAP(Windows::Networking::Connectivity::NetworkSecuritySettings));
            *value = detach_from<Windows::Networking::Connectivity::NetworkSecuritySettings>(this->shim().NetworkSecuritySettings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectionProfile2> : produce_base<D, Windows::Networking::Connectivity::IConnectionProfile2>
{
    int32_t WINRT_CALL get_IsWwanConnectionProfile(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWwanConnectionProfile, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsWwanConnectionProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsWlanConnectionProfile(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWlanConnectionProfile, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsWlanConnectionProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WwanConnectionProfileDetails(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WwanConnectionProfileDetails, WINRT_WRAP(Windows::Networking::Connectivity::WwanConnectionProfileDetails));
            *value = detach_from<Windows::Networking::Connectivity::WwanConnectionProfileDetails>(this->shim().WwanConnectionProfileDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WlanConnectionProfileDetails(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WlanConnectionProfileDetails, WINRT_WRAP(Windows::Networking::Connectivity::WlanConnectionProfileDetails));
            *value = detach_from<Windows::Networking::Connectivity::WlanConnectionProfileDetails>(this->shim().WlanConnectionProfileDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceProviderGuid(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceProviderGuid, WINRT_WRAP(Windows::Foundation::IReference<winrt::guid>));
            *value = detach_from<Windows::Foundation::IReference<winrt::guid>>(this->shim().ServiceProviderGuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSignalBars(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSignalBars, WINRT_WRAP(Windows::Foundation::IReference<uint8_t>));
            *value = detach_from<Windows::Foundation::IReference<uint8_t>>(this->shim().GetSignalBars());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDomainConnectivityLevel(Windows::Networking::Connectivity::DomainConnectivityLevel* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDomainConnectivityLevel, WINRT_WRAP(Windows::Networking::Connectivity::DomainConnectivityLevel));
            *value = detach_from<Windows::Networking::Connectivity::DomainConnectivityLevel>(this->shim().GetDomainConnectivityLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNetworkUsageAsync(Windows::Foundation::DateTime startTime, Windows::Foundation::DateTime endTime, Windows::Networking::Connectivity::DataUsageGranularity granularity, struct struct_Windows_Networking_Connectivity_NetworkUsageStates states, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNetworkUsageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::NetworkUsage>>), Windows::Foundation::DateTime const, Windows::Foundation::DateTime const, Windows::Networking::Connectivity::DataUsageGranularity const, Windows::Networking::Connectivity::NetworkUsageStates const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::NetworkUsage>>>(this->shim().GetNetworkUsageAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::Foundation::DateTime const*>(&endTime), *reinterpret_cast<Windows::Networking::Connectivity::DataUsageGranularity const*>(&granularity), *reinterpret_cast<Windows::Networking::Connectivity::NetworkUsageStates const*>(&states)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConnectivityIntervalsAsync(Windows::Foundation::DateTime startTime, Windows::Foundation::DateTime endTime, struct struct_Windows_Networking_Connectivity_NetworkUsageStates states, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConnectivityIntervalsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectivityInterval>>), Windows::Foundation::DateTime const, Windows::Foundation::DateTime const, Windows::Networking::Connectivity::NetworkUsageStates const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectivityInterval>>>(this->shim().GetConnectivityIntervalsAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::Foundation::DateTime const*>(&endTime), *reinterpret_cast<Windows::Networking::Connectivity::NetworkUsageStates const*>(&states)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectionProfile3> : produce_base<D, Windows::Networking::Connectivity::IConnectionProfile3>
{
    int32_t WINRT_CALL GetAttributedNetworkUsageAsync(Windows::Foundation::DateTime startTime, Windows::Foundation::DateTime endTime, struct struct_Windows_Networking_Connectivity_NetworkUsageStates states, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAttributedNetworkUsageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::AttributedNetworkUsage>>), Windows::Foundation::DateTime const, Windows::Foundation::DateTime const, Windows::Networking::Connectivity::NetworkUsageStates const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::AttributedNetworkUsage>>>(this->shim().GetAttributedNetworkUsageAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::Foundation::DateTime const*>(&endTime), *reinterpret_cast<Windows::Networking::Connectivity::NetworkUsageStates const*>(&states)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectionProfile4> : produce_base<D, Windows::Networking::Connectivity::IConnectionProfile4>
{
    int32_t WINRT_CALL GetProviderNetworkUsageAsync(Windows::Foundation::DateTime startTime, Windows::Foundation::DateTime endTime, struct struct_Windows_Networking_Connectivity_NetworkUsageStates states, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProviderNetworkUsageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ProviderNetworkUsage>>), Windows::Foundation::DateTime const, Windows::Foundation::DateTime const, Windows::Networking::Connectivity::NetworkUsageStates const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ProviderNetworkUsage>>>(this->shim().GetProviderNetworkUsageAsync(*reinterpret_cast<Windows::Foundation::DateTime const*>(&startTime), *reinterpret_cast<Windows::Foundation::DateTime const*>(&endTime), *reinterpret_cast<Windows::Networking::Connectivity::NetworkUsageStates const*>(&states)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectionProfile5> : produce_base<D, Windows::Networking::Connectivity::IConnectionProfile5>
{
    int32_t WINRT_CALL get_CanDelete(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanDelete, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanDelete());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryDeleteAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryDeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionProfileDeleteStatus>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionProfileDeleteStatus>>(this->shim().TryDeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectionProfileFilter> : produce_base<D, Windows::Networking::Connectivity::IConnectionProfileFilter>
{
    int32_t WINRT_CALL put_IsConnected(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsConnected, WINRT_WRAP(void), bool);
            this->shim().IsConnected(value);
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

    int32_t WINRT_CALL put_IsWwanConnectionProfile(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWwanConnectionProfile, WINRT_WRAP(void), bool);
            this->shim().IsWwanConnectionProfile(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsWwanConnectionProfile(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWwanConnectionProfile, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsWwanConnectionProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsWlanConnectionProfile(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWlanConnectionProfile, WINRT_WRAP(void), bool);
            this->shim().IsWlanConnectionProfile(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsWlanConnectionProfile(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsWlanConnectionProfile, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsWlanConnectionProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NetworkCostType(Windows::Networking::Connectivity::NetworkCostType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkCostType, WINRT_WRAP(void), Windows::Networking::Connectivity::NetworkCostType const&);
            this->shim().NetworkCostType(*reinterpret_cast<Windows::Networking::Connectivity::NetworkCostType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkCostType(Windows::Networking::Connectivity::NetworkCostType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkCostType, WINRT_WRAP(Windows::Networking::Connectivity::NetworkCostType));
            *value = detach_from<Windows::Networking::Connectivity::NetworkCostType>(this->shim().NetworkCostType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ServiceProviderGuid(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceProviderGuid, WINRT_WRAP(void), Windows::Foundation::IReference<winrt::guid> const&);
            this->shim().ServiceProviderGuid(*reinterpret_cast<Windows::Foundation::IReference<winrt::guid> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ServiceProviderGuid(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ServiceProviderGuid, WINRT_WRAP(Windows::Foundation::IReference<winrt::guid>));
            *value = detach_from<Windows::Foundation::IReference<winrt::guid>>(this->shim().ServiceProviderGuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectionProfileFilter2> : produce_base<D, Windows::Networking::Connectivity::IConnectionProfileFilter2>
{
    int32_t WINRT_CALL put_IsRoaming(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRoaming, WINRT_WRAP(void), Windows::Foundation::IReference<bool> const&);
            this->shim().IsRoaming(*reinterpret_cast<Windows::Foundation::IReference<bool> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRoaming(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRoaming, WINRT_WRAP(Windows::Foundation::IReference<bool>));
            *value = detach_from<Windows::Foundation::IReference<bool>>(this->shim().IsRoaming());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsOverDataLimit(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverDataLimit, WINRT_WRAP(void), Windows::Foundation::IReference<bool> const&);
            this->shim().IsOverDataLimit(*reinterpret_cast<Windows::Foundation::IReference<bool> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsOverDataLimit(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsOverDataLimit, WINRT_WRAP(Windows::Foundation::IReference<bool>));
            *value = detach_from<Windows::Foundation::IReference<bool>>(this->shim().IsOverDataLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsBackgroundDataUsageRestricted(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBackgroundDataUsageRestricted, WINRT_WRAP(void), Windows::Foundation::IReference<bool> const&);
            this->shim().IsBackgroundDataUsageRestricted(*reinterpret_cast<Windows::Foundation::IReference<bool> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsBackgroundDataUsageRestricted(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsBackgroundDataUsageRestricted, WINRT_WRAP(Windows::Foundation::IReference<bool>));
            *value = detach_from<Windows::Foundation::IReference<bool>>(this->shim().IsBackgroundDataUsageRestricted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RawData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RawData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().RawData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectionProfileFilter3> : produce_base<D, Windows::Networking::Connectivity::IConnectionProfileFilter3>
{
    int32_t WINRT_CALL put_PurposeGuid(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PurposeGuid, WINRT_WRAP(void), Windows::Foundation::IReference<winrt::guid> const&);
            this->shim().PurposeGuid(*reinterpret_cast<Windows::Foundation::IReference<winrt::guid> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PurposeGuid(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PurposeGuid, WINRT_WRAP(Windows::Foundation::IReference<winrt::guid>));
            *value = detach_from<Windows::Foundation::IReference<winrt::guid>>(this->shim().PurposeGuid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectionSession> : produce_base<D, Windows::Networking::Connectivity::IConnectionSession>
{
    int32_t WINRT_CALL get_ConnectionProfile(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionProfile, WINRT_WRAP(Windows::Networking::Connectivity::ConnectionProfile));
            *value = detach_from<Windows::Networking::Connectivity::ConnectionProfile>(this->shim().ConnectionProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectivityInterval> : produce_base<D, Windows::Networking::Connectivity::IConnectivityInterval>
{
    int32_t WINRT_CALL get_StartTime(Windows::Foundation::DateTime* startTime) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *startTime = detach_from<Windows::Foundation::DateTime>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionDuration(Windows::Foundation::TimeSpan* duration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *duration = detach_from<Windows::Foundation::TimeSpan>(this->shim().ConnectionDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IConnectivityManagerStatics> : produce_base<D, Windows::Networking::Connectivity::IConnectivityManagerStatics>
{
    int32_t WINRT_CALL AcquireConnectionAsync(void* cellularApnContext, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AcquireConnectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionSession>), Windows::Networking::Connectivity::CellularApnContext const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionSession>>(this->shim().AcquireConnectionAsync(*reinterpret_cast<Windows::Networking::Connectivity::CellularApnContext const*>(&cellularApnContext)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddHttpRoutePolicy(void* routePolicy) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddHttpRoutePolicy, WINRT_WRAP(void), Windows::Networking::Connectivity::RoutePolicy const&);
            this->shim().AddHttpRoutePolicy(*reinterpret_cast<Windows::Networking::Connectivity::RoutePolicy const*>(&routePolicy));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveHttpRoutePolicy(void* routePolicy) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveHttpRoutePolicy, WINRT_WRAP(void), Windows::Networking::Connectivity::RoutePolicy const&);
            this->shim().RemoveHttpRoutePolicy(*reinterpret_cast<Windows::Networking::Connectivity::RoutePolicy const*>(&routePolicy));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IDataPlanStatus> : produce_base<D, Windows::Networking::Connectivity::IDataPlanStatus>
{
    int32_t WINRT_CALL get_DataPlanUsage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataPlanUsage, WINRT_WRAP(Windows::Networking::Connectivity::DataPlanUsage));
            *value = detach_from<Windows::Networking::Connectivity::DataPlanUsage>(this->shim().DataPlanUsage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DataLimitInMegabytes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataLimitInMegabytes, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().DataLimitInMegabytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InboundBitsPerSecond(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InboundBitsPerSecond, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().InboundBitsPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutboundBitsPerSecond(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundBitsPerSecond, WINRT_WRAP(Windows::Foundation::IReference<uint64_t>));
            *value = detach_from<Windows::Foundation::IReference<uint64_t>>(this->shim().OutboundBitsPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NextBillingCycle(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NextBillingCycle, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().NextBillingCycle());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxTransferSizeInMegabytes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxTransferSizeInMegabytes, WINRT_WRAP(Windows::Foundation::IReference<uint32_t>));
            *value = detach_from<Windows::Foundation::IReference<uint32_t>>(this->shim().MaxTransferSizeInMegabytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IDataPlanUsage> : produce_base<D, Windows::Networking::Connectivity::IDataPlanUsage>
{
    int32_t WINRT_CALL get_MegabytesUsed(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MegabytesUsed, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MegabytesUsed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastSyncTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastSyncTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().LastSyncTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IDataUsage> : produce_base<D, Windows::Networking::Connectivity::IDataUsage>
{
    int32_t WINRT_CALL get_BytesSent(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesSent, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BytesSent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BytesReceived(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesReceived, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BytesReceived());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IIPInformation> : produce_base<D, Windows::Networking::Connectivity::IIPInformation>
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

    int32_t WINRT_CALL get_PrefixLength(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrefixLength, WINRT_WRAP(Windows::Foundation::IReference<uint8_t>));
            *value = detach_from<Windows::Foundation::IReference<uint8_t>>(this->shim().PrefixLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::ILanIdentifier> : produce_base<D, Windows::Networking::Connectivity::ILanIdentifier>
{
    int32_t WINRT_CALL get_InfrastructureId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InfrastructureId, WINRT_WRAP(Windows::Networking::Connectivity::LanIdentifierData));
            *value = detach_from<Windows::Networking::Connectivity::LanIdentifierData>(this->shim().InfrastructureId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PortId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PortId, WINRT_WRAP(Windows::Networking::Connectivity::LanIdentifierData));
            *value = detach_from<Windows::Networking::Connectivity::LanIdentifierData>(this->shim().PortId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkAdapterId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAdapterId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().NetworkAdapterId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::ILanIdentifierData> : produce_base<D, Windows::Networking::Connectivity::ILanIdentifierData>
{
    int32_t WINRT_CALL get_Type(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint8_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint8_t>>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::INetworkAdapter> : produce_base<D, Windows::Networking::Connectivity::INetworkAdapter>
{
    int32_t WINRT_CALL get_OutboundMaxBitsPerSecond(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutboundMaxBitsPerSecond, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().OutboundMaxBitsPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InboundMaxBitsPerSecond(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InboundMaxBitsPerSecond, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().InboundMaxBitsPerSecond());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IanaInterfaceType(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IanaInterfaceType, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().IanaInterfaceType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkItem, WINRT_WRAP(Windows::Networking::Connectivity::NetworkItem));
            *value = detach_from<Windows::Networking::Connectivity::NetworkItem>(this->shim().NetworkItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkAdapterId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAdapterId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().NetworkAdapterId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetConnectedProfileAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConnectedProfileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionProfile>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionProfile>>(this->shim().GetConnectedProfileAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::INetworkInformationStatics> : produce_base<D, Windows::Networking::Connectivity::INetworkInformationStatics>
{
    int32_t WINRT_CALL GetConnectionProfiles(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConnectionProfiles, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile>>(this->shim().GetConnectionProfiles());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetInternetConnectionProfile(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetInternetConnectionProfile, WINRT_WRAP(Windows::Networking::Connectivity::ConnectionProfile));
            *value = detach_from<Windows::Networking::Connectivity::ConnectionProfile>(this->shim().GetInternetConnectionProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLanIdentifiers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLanIdentifiers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::LanIdentifier>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::LanIdentifier>>(this->shim().GetLanIdentifiers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetHostNames(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetHostNames, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName>>(this->shim().GetHostNames());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetProxyConfigurationAsync(void* uri, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetProxyConfigurationAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ProxyConfiguration>), Windows::Foundation::Uri const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ProxyConfiguration>>(this->shim().GetProxyConfigurationAsync(*reinterpret_cast<Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSortedEndpointPairs(void* destinationList, Windows::Networking::HostNameSortOptions sortOptions, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSortedEndpointPairs, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>), Windows::Foundation::Collections::IIterable<Windows::Networking::EndpointPair> const&, Windows::Networking::HostNameSortOptions const&);
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair>>(this->shim().GetSortedEndpointPairs(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Networking::EndpointPair> const*>(&destinationList), *reinterpret_cast<Windows::Networking::HostNameSortOptions const*>(&sortOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_NetworkStatusChanged(void* networkStatusHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Networking::Connectivity::NetworkStatusChangedEventHandler const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().NetworkStatusChanged(*reinterpret_cast<Windows::Networking::Connectivity::NetworkStatusChangedEventHandler const*>(&networkStatusHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_NetworkStatusChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(NetworkStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().NetworkStatusChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::INetworkInformationStatics2> : produce_base<D, Windows::Networking::Connectivity::INetworkInformationStatics2>
{
    int32_t WINRT_CALL FindConnectionProfilesAsync(void* pProfileFilter, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindConnectionProfilesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile>>), Windows::Networking::Connectivity::ConnectionProfileFilter const);
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile>>>(this->shim().FindConnectionProfilesAsync(*reinterpret_cast<Windows::Networking::Connectivity::ConnectionProfileFilter const*>(&pProfileFilter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::INetworkItem> : produce_base<D, Windows::Networking::Connectivity::INetworkItem>
{
    int32_t WINRT_CALL get_NetworkId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().NetworkId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNetworkTypes(Windows::Networking::Connectivity::NetworkTypes* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNetworkTypes, WINRT_WRAP(Windows::Networking::Connectivity::NetworkTypes));
            *value = detach_from<Windows::Networking::Connectivity::NetworkTypes>(this->shim().GetNetworkTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::INetworkSecuritySettings> : produce_base<D, Windows::Networking::Connectivity::INetworkSecuritySettings>
{
    int32_t WINRT_CALL get_NetworkAuthenticationType(Windows::Networking::Connectivity::NetworkAuthenticationType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkAuthenticationType, WINRT_WRAP(Windows::Networking::Connectivity::NetworkAuthenticationType));
            *value = detach_from<Windows::Networking::Connectivity::NetworkAuthenticationType>(this->shim().NetworkAuthenticationType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NetworkEncryptionType(Windows::Networking::Connectivity::NetworkEncryptionType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NetworkEncryptionType, WINRT_WRAP(Windows::Networking::Connectivity::NetworkEncryptionType));
            *value = detach_from<Windows::Networking::Connectivity::NetworkEncryptionType>(this->shim().NetworkEncryptionType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::INetworkStateChangeEventDetails> : produce_base<D, Windows::Networking::Connectivity::INetworkStateChangeEventDetails>
{
    int32_t WINRT_CALL get_HasNewInternetConnectionProfile(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNewInternetConnectionProfile, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasNewInternetConnectionProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasNewConnectionCost(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNewConnectionCost, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasNewConnectionCost());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasNewNetworkConnectivityLevel(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNewNetworkConnectivityLevel, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasNewNetworkConnectivityLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasNewDomainConnectivityLevel(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNewDomainConnectivityLevel, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasNewDomainConnectivityLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasNewHostNameList(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNewHostNameList, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasNewHostNameList());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasNewWwanRegistrationState(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNewWwanRegistrationState, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasNewWwanRegistrationState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::INetworkStateChangeEventDetails2> : produce_base<D, Windows::Networking::Connectivity::INetworkStateChangeEventDetails2>
{
    int32_t WINRT_CALL get_HasNewTetheringOperationalState(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNewTetheringOperationalState, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasNewTetheringOperationalState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasNewTetheringClientCount(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasNewTetheringClientCount, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasNewTetheringClientCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::INetworkUsage> : produce_base<D, Windows::Networking::Connectivity::INetworkUsage>
{
    int32_t WINRT_CALL get_BytesSent(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesSent, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BytesSent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BytesReceived(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesReceived, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BytesReceived());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConnectionDuration(Windows::Foundation::TimeSpan* duration) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *duration = detach_from<Windows::Foundation::TimeSpan>(this->shim().ConnectionDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IProviderNetworkUsage> : produce_base<D, Windows::Networking::Connectivity::IProviderNetworkUsage>
{
    int32_t WINRT_CALL get_BytesSent(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesSent, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BytesSent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BytesReceived(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BytesReceived, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().BytesReceived());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ProviderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IProxyConfiguration> : produce_base<D, Windows::Networking::Connectivity::IProxyConfiguration>
{
    int32_t WINRT_CALL get_ProxyUris(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProxyUris, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Foundation::Uri>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Uri>>(this->shim().ProxyUris());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanConnectDirectly(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanConnectDirectly, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanConnectDirectly());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IRoutePolicy> : produce_base<D, Windows::Networking::Connectivity::IRoutePolicy>
{
    int32_t WINRT_CALL get_ConnectionProfile(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConnectionProfile, WINRT_WRAP(Windows::Networking::Connectivity::ConnectionProfile));
            *value = detach_from<Windows::Networking::Connectivity::ConnectionProfile>(this->shim().ConnectionProfile());
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

    int32_t WINRT_CALL get_HostNameType(Windows::Networking::DomainNameType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HostNameType, WINRT_WRAP(Windows::Networking::DomainNameType));
            *value = detach_from<Windows::Networking::DomainNameType>(this->shim().HostNameType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IRoutePolicyFactory> : produce_base<D, Windows::Networking::Connectivity::IRoutePolicyFactory>
{
    int32_t WINRT_CALL CreateRoutePolicy(void* connectionProfile, void* hostName, Windows::Networking::DomainNameType type, void** routePolicy) noexcept final
    {
        try
        {
            *routePolicy = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateRoutePolicy, WINRT_WRAP(Windows::Networking::Connectivity::RoutePolicy), Windows::Networking::Connectivity::ConnectionProfile const&, Windows::Networking::HostName const&, Windows::Networking::DomainNameType const&);
            *routePolicy = detach_from<Windows::Networking::Connectivity::RoutePolicy>(this->shim().CreateRoutePolicy(*reinterpret_cast<Windows::Networking::Connectivity::ConnectionProfile const*>(&connectionProfile), *reinterpret_cast<Windows::Networking::HostName const*>(&hostName), *reinterpret_cast<Windows::Networking::DomainNameType const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IWlanConnectionProfileDetails> : produce_base<D, Windows::Networking::Connectivity::IWlanConnectionProfileDetails>
{
    int32_t WINRT_CALL GetConnectedSsid(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetConnectedSsid, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GetConnectedSsid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IWwanConnectionProfileDetails> : produce_base<D, Windows::Networking::Connectivity::IWwanConnectionProfileDetails>
{
    int32_t WINRT_CALL get_HomeProviderId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HomeProviderId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HomeProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AccessPointName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AccessPointName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AccessPointName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNetworkRegistrationState(Windows::Networking::Connectivity::WwanNetworkRegistrationState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNetworkRegistrationState, WINRT_WRAP(Windows::Networking::Connectivity::WwanNetworkRegistrationState));
            *value = detach_from<Windows::Networking::Connectivity::WwanNetworkRegistrationState>(this->shim().GetNetworkRegistrationState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentDataClass(Windows::Networking::Connectivity::WwanDataClass* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentDataClass, WINRT_WRAP(Windows::Networking::Connectivity::WwanDataClass));
            *value = detach_from<Windows::Networking::Connectivity::WwanDataClass>(this->shim().GetCurrentDataClass());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Networking::Connectivity::IWwanConnectionProfileDetails2> : produce_base<D, Windows::Networking::Connectivity::IWwanConnectionProfileDetails2>
{
    int32_t WINRT_CALL get_IPKind(Windows::Networking::Connectivity::WwanNetworkIPKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IPKind, WINRT_WRAP(Windows::Networking::Connectivity::WwanNetworkIPKind));
            *value = detach_from<Windows::Networking::Connectivity::WwanNetworkIPKind>(this->shim().IPKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PurposeGuids(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PurposeGuids, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<winrt::guid>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<winrt::guid>>(this->shim().PurposeGuids());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Networking::Connectivity {

inline CellularApnContext::CellularApnContext() :
    CellularApnContext(impl::call_factory<CellularApnContext>([](auto&& f) { return f.template ActivateInstance<CellularApnContext>(); }))
{}

inline ConnectionProfileFilter::ConnectionProfileFilter() :
    ConnectionProfileFilter(impl::call_factory<ConnectionProfileFilter>([](auto&& f) { return f.template ActivateInstance<ConnectionProfileFilter>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ConnectionSession> ConnectivityManager::AcquireConnectionAsync(Windows::Networking::Connectivity::CellularApnContext const& cellularApnContext)
{
    return impl::call_factory<ConnectivityManager, Windows::Networking::Connectivity::IConnectivityManagerStatics>([&](auto&& f) { return f.AcquireConnectionAsync(cellularApnContext); });
}

inline void ConnectivityManager::AddHttpRoutePolicy(Windows::Networking::Connectivity::RoutePolicy const& routePolicy)
{
    impl::call_factory<ConnectivityManager, Windows::Networking::Connectivity::IConnectivityManagerStatics>([&](auto&& f) { return f.AddHttpRoutePolicy(routePolicy); });
}

inline void ConnectivityManager::RemoveHttpRoutePolicy(Windows::Networking::Connectivity::RoutePolicy const& routePolicy)
{
    impl::call_factory<ConnectivityManager, Windows::Networking::Connectivity::IConnectivityManagerStatics>([&](auto&& f) { return f.RemoveHttpRoutePolicy(routePolicy); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile> NetworkInformation::GetConnectionProfiles()
{
    return impl::call_factory<NetworkInformation, Windows::Networking::Connectivity::INetworkInformationStatics>([&](auto&& f) { return f.GetConnectionProfiles(); });
}

inline Windows::Networking::Connectivity::ConnectionProfile NetworkInformation::GetInternetConnectionProfile()
{
    return impl::call_factory<NetworkInformation, Windows::Networking::Connectivity::INetworkInformationStatics>([&](auto&& f) { return f.GetInternetConnectionProfile(); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::LanIdentifier> NetworkInformation::GetLanIdentifiers()
{
    return impl::call_factory<NetworkInformation, Windows::Networking::Connectivity::INetworkInformationStatics>([&](auto&& f) { return f.GetLanIdentifiers(); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Networking::HostName> NetworkInformation::GetHostNames()
{
    return impl::call_factory<NetworkInformation, Windows::Networking::Connectivity::INetworkInformationStatics>([&](auto&& f) { return f.GetHostNames(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Networking::Connectivity::ProxyConfiguration> NetworkInformation::GetProxyConfigurationAsync(Windows::Foundation::Uri const& uri)
{
    return impl::call_factory<NetworkInformation, Windows::Networking::Connectivity::INetworkInformationStatics>([&](auto&& f) { return f.GetProxyConfigurationAsync(uri); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Networking::EndpointPair> NetworkInformation::GetSortedEndpointPairs(param::iterable<Windows::Networking::EndpointPair> const& destinationList, Windows::Networking::HostNameSortOptions const& sortOptions)
{
    return impl::call_factory<NetworkInformation, Windows::Networking::Connectivity::INetworkInformationStatics>([&](auto&& f) { return f.GetSortedEndpointPairs(destinationList, sortOptions); });
}

inline winrt::event_token NetworkInformation::NetworkStatusChanged(Windows::Networking::Connectivity::NetworkStatusChangedEventHandler const& networkStatusHandler)
{
    return impl::call_factory<NetworkInformation, Windows::Networking::Connectivity::INetworkInformationStatics>([&](auto&& f) { return f.NetworkStatusChanged(networkStatusHandler); });
}

inline NetworkInformation::NetworkStatusChanged_revoker NetworkInformation::NetworkStatusChanged(auto_revoke_t, Windows::Networking::Connectivity::NetworkStatusChangedEventHandler const& networkStatusHandler)
{
    auto f = get_activation_factory<NetworkInformation, Windows::Networking::Connectivity::INetworkInformationStatics>();
    return { f, f.NetworkStatusChanged(networkStatusHandler) };
}

inline void NetworkInformation::NetworkStatusChanged(winrt::event_token const& eventCookie)
{
    impl::call_factory<NetworkInformation, Windows::Networking::Connectivity::INetworkInformationStatics>([&](auto&& f) { return f.NetworkStatusChanged(eventCookie); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::Networking::Connectivity::ConnectionProfile>> NetworkInformation::FindConnectionProfilesAsync(Windows::Networking::Connectivity::ConnectionProfileFilter const& pProfileFilter)
{
    return impl::call_factory<NetworkInformation, Windows::Networking::Connectivity::INetworkInformationStatics2>([&](auto&& f) { return f.FindConnectionProfilesAsync(pProfileFilter); });
}

inline RoutePolicy::RoutePolicy(Windows::Networking::Connectivity::ConnectionProfile const& connectionProfile, Windows::Networking::HostName const& hostName, Windows::Networking::DomainNameType const& type) :
    RoutePolicy(impl::call_factory<RoutePolicy, Windows::Networking::Connectivity::IRoutePolicyFactory>([&](auto&& f) { return f.CreateRoutePolicy(connectionProfile, hostName, type); }))
{}

template <typename L> NetworkStatusChangedEventHandler::NetworkStatusChangedEventHandler(L handler) :
    NetworkStatusChangedEventHandler(impl::make_delegate<NetworkStatusChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> NetworkStatusChangedEventHandler::NetworkStatusChangedEventHandler(F* handler) :
    NetworkStatusChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> NetworkStatusChangedEventHandler::NetworkStatusChangedEventHandler(O* object, M method) :
    NetworkStatusChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> NetworkStatusChangedEventHandler::NetworkStatusChangedEventHandler(com_ptr<O>&& object, M method) :
    NetworkStatusChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> NetworkStatusChangedEventHandler::NetworkStatusChangedEventHandler(weak_ref<O>&& object, M method) :
    NetworkStatusChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void NetworkStatusChangedEventHandler::operator()(Windows::Foundation::IInspectable const& sender) const
{
    check_hresult((*(impl::abi_t<NetworkStatusChangedEventHandler>**)this)->Invoke(get_abi(sender)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Networking::Connectivity::IAttributedNetworkUsage> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IAttributedNetworkUsage> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ICellularApnContext> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ICellularApnContext> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ICellularApnContext2> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ICellularApnContext2> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectionCost> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectionCost> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectionCost2> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectionCost2> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectionProfile> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectionProfile> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectionProfile2> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectionProfile2> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectionProfile3> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectionProfile3> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectionProfile4> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectionProfile4> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectionProfile5> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectionProfile5> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectionProfileFilter> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectionProfileFilter> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectionProfileFilter2> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectionProfileFilter2> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectionProfileFilter3> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectionProfileFilter3> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectionSession> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectionSession> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectivityInterval> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectivityInterval> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IConnectivityManagerStatics> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IConnectivityManagerStatics> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IDataPlanStatus> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IDataPlanStatus> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IDataPlanUsage> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IDataPlanUsage> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IDataUsage> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IDataUsage> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IIPInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IIPInformation> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ILanIdentifier> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ILanIdentifier> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ILanIdentifierData> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ILanIdentifierData> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::INetworkAdapter> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::INetworkAdapter> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::INetworkInformationStatics> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::INetworkInformationStatics> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::INetworkInformationStatics2> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::INetworkInformationStatics2> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::INetworkItem> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::INetworkItem> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::INetworkSecuritySettings> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::INetworkSecuritySettings> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::INetworkStateChangeEventDetails> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::INetworkStateChangeEventDetails> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::INetworkStateChangeEventDetails2> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::INetworkStateChangeEventDetails2> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::INetworkUsage> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::INetworkUsage> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IProviderNetworkUsage> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IProviderNetworkUsage> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IProxyConfiguration> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IProxyConfiguration> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IRoutePolicy> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IRoutePolicy> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IRoutePolicyFactory> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IRoutePolicyFactory> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IWlanConnectionProfileDetails> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IWlanConnectionProfileDetails> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IWwanConnectionProfileDetails> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IWwanConnectionProfileDetails> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IWwanConnectionProfileDetails2> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IWwanConnectionProfileDetails2> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::AttributedNetworkUsage> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::AttributedNetworkUsage> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::CellularApnContext> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::CellularApnContext> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ConnectionCost> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ConnectionCost> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ConnectionProfile> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ConnectionProfile> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ConnectionProfileFilter> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ConnectionProfileFilter> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ConnectionSession> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ConnectionSession> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ConnectivityInterval> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ConnectivityInterval> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ConnectivityManager> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ConnectivityManager> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::DataPlanStatus> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::DataPlanStatus> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::DataPlanUsage> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::DataPlanUsage> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::DataUsage> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::DataUsage> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::IPInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::IPInformation> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::LanIdentifier> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::LanIdentifier> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::LanIdentifierData> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::LanIdentifierData> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::NetworkAdapter> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::NetworkAdapter> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::NetworkInformation> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::NetworkInformation> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::NetworkItem> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::NetworkItem> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::NetworkSecuritySettings> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::NetworkSecuritySettings> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::NetworkStateChangeEventDetails> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::NetworkStateChangeEventDetails> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::NetworkUsage> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::NetworkUsage> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ProviderNetworkUsage> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ProviderNetworkUsage> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::ProxyConfiguration> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::ProxyConfiguration> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::RoutePolicy> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::RoutePolicy> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::WlanConnectionProfileDetails> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::WlanConnectionProfileDetails> {};
template<> struct hash<winrt::Windows::Networking::Connectivity::WwanConnectionProfileDetails> : winrt::impl::hash_base<winrt::Windows::Networking::Connectivity::WwanConnectionProfileDetails> {};

}
