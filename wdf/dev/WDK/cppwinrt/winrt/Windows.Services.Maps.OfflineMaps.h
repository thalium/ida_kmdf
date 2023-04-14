// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.Services.Maps.OfflineMaps.2.h"
#include "winrt/Windows.Services.Maps.h"

namespace winrt::impl {

template <typename D> Windows::Services::Maps::OfflineMaps::OfflineMapPackageStatus consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::Status() const
{
    Windows::Services::Maps::OfflineMaps::OfflineMapPackageStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::EnclosingRegionName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->get_EnclosingRegionName(put_abi(value)));
    return value;
}

template <typename D> uint64_t consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::EstimatedSizeInBytes() const
{
    uint64_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->get_EstimatedSizeInBytes(&value));
    return value;
}

template <typename D> void consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::StatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->remove_StatusChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::StatusChanged(Windows::Foundation::TypedEventHandler<Windows::Services::Maps::OfflineMaps::OfflineMapPackage, Windows::Foundation::IInspectable> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->add_StatusChanged(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::StatusChanged_revoker consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::StatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::Maps::OfflineMaps::OfflineMapPackage, Windows::Foundation::IInspectable> const& value) const
{
    return impl::make_event_revoker<D, StatusChanged_revoker>(this, StatusChanged(value));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadResult> consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackage<D>::RequestStartDownloadAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadResult> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackage)->RequestStartDownloadAsync(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryStatus consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageQueryResult<D>::Status() const
{
    Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::OfflineMaps::OfflineMapPackage> consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageQueryResult<D>::Packages() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::OfflineMaps::OfflineMapPackage> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult)->get_Packages(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadStatus consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageStartDownloadResult<D>::Status() const
{
    Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadStatus value{};
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStartDownloadResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageStatics<D>::FindPackagesAsync(Windows::Devices::Geolocation::Geopoint const& queryPoint) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics)->FindPackagesAsync(get_abi(queryPoint), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageStatics<D>::FindPackagesInBoundingBoxAsync(Windows::Devices::Geolocation::GeoboundingBox const& queryBoundingBox) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics)->FindPackagesInBoundingBoxAsync(get_abi(queryBoundingBox), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> consume_Windows_Services_Maps_OfflineMaps_IOfflineMapPackageStatics<D>::FindPackagesInGeocircleAsync(Windows::Devices::Geolocation::Geocircle const& queryCircle) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics)->FindPackagesInGeocircleAsync(get_abi(queryCircle), put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::Services::Maps::OfflineMaps::IOfflineMapPackage> : produce_base<D, Windows::Services::Maps::OfflineMaps::IOfflineMapPackage>
{
    int32_t WINRT_CALL get_Status(Windows::Services::Maps::OfflineMaps::OfflineMapPackageStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Maps::OfflineMaps::OfflineMapPackageStatus));
            *value = detach_from<Windows::Services::Maps::OfflineMaps::OfflineMapPackageStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EnclosingRegionName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnclosingRegionName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EnclosingRegionName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EstimatedSizeInBytes(uint64_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EstimatedSizeInBytes, WINRT_WRAP(uint64_t));
            *value = detach_from<uint64_t>(this->shim().EstimatedSizeInBytes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_StatusChanged(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::Maps::OfflineMaps::OfflineMapPackage, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().StatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::Maps::OfflineMaps::OfflineMapPackage, Windows::Foundation::IInspectable> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestStartDownloadAsync(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestStartDownloadAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadResult>));
            *value = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadResult>>(this->shim().RequestStartDownloadAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult> : produce_base<D, Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult>
{
    int32_t WINRT_CALL get_Status(Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryStatus));
            *value = detach_from<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Packages(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Packages, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::OfflineMaps::OfflineMapPackage>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::OfflineMaps::OfflineMapPackage>>(this->shim().Packages());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStartDownloadResult> : produce_base<D, Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStartDownloadResult>
{
    int32_t WINRT_CALL get_Status(Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadStatus));
            *value = detach_from<Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics> : produce_base<D, Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics>
{
    int32_t WINRT_CALL FindPackagesAsync(void* queryPoint, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>), Windows::Devices::Geolocation::Geopoint const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>>(this->shim().FindPackagesAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&queryPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesInBoundingBoxAsync(void* queryBoundingBox, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesInBoundingBoxAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>), Windows::Devices::Geolocation::GeoboundingBox const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>>(this->shim().FindPackagesInBoundingBoxAsync(*reinterpret_cast<Windows::Devices::Geolocation::GeoboundingBox const*>(&queryBoundingBox)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindPackagesInGeocircleAsync(void* queryCircle, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindPackagesInGeocircleAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>), Windows::Devices::Geolocation::Geocircle const);
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult>>(this->shim().FindPackagesInGeocircleAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geocircle const*>(&queryCircle)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Services::Maps::OfflineMaps {

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> OfflineMapPackage::FindPackagesAsync(Windows::Devices::Geolocation::Geopoint const& queryPoint)
{
    return impl::call_factory<OfflineMapPackage, Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics>([&](auto&& f) { return f.FindPackagesAsync(queryPoint); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> OfflineMapPackage::FindPackagesInBoundingBoxAsync(Windows::Devices::Geolocation::GeoboundingBox const& queryBoundingBox)
{
    return impl::call_factory<OfflineMapPackage, Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics>([&](auto&& f) { return f.FindPackagesInBoundingBoxAsync(queryBoundingBox); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> OfflineMapPackage::FindPackagesInGeocircleAsync(Windows::Devices::Geolocation::Geocircle const& queryCircle)
{
    return impl::call_factory<OfflineMapPackage, Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics>([&](auto&& f) { return f.FindPackagesInGeocircleAsync(queryCircle); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage> : winrt::impl::hash_base<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackage> {};
template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult> : winrt::impl::hash_base<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageQueryResult> {};
template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStartDownloadResult> : winrt::impl::hash_base<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStartDownloadResult> {};
template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics> : winrt::impl::hash_base<winrt::Windows::Services::Maps::OfflineMaps::IOfflineMapPackageStatics> {};
template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackage> : winrt::impl::hash_base<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackage> {};
template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> : winrt::impl::hash_base<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageQueryResult> {};
template<> struct hash<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadResult> : winrt::impl::hash_base<winrt::Windows::Services::Maps::OfflineMaps::OfflineMapPackageStartDownloadResult> {};

}
