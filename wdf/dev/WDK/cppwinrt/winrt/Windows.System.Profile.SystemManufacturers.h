// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.System.Profile.SystemManufacturers.2.h"
#include "winrt/Windows.System.Profile.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Uri consume_Windows_System_Profile_SystemManufacturers_IOemSupportInfo<D>::SupportLink() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::IOemSupportInfo)->get_SupportLink(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_System_Profile_SystemManufacturers_IOemSupportInfo<D>::SupportAppLink() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::IOemSupportInfo)->get_SupportAppLink(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_SystemManufacturers_IOemSupportInfo<D>::SupportProvider() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::IOemSupportInfo)->get_SupportProvider(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_SystemManufacturers_ISmbiosInformationStatics<D>::SerialNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::ISmbiosInformationStatics)->get_SerialNumber(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::OperatingSystem() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_OperatingSystem(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::FriendlyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_FriendlyName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::SystemManufacturer() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_SystemManufacturer(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::SystemProductName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_SystemProductName(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::SystemSku() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_SystemSku(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::SystemHardwareVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_SystemHardwareVersion(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_SystemManufacturers_ISystemSupportDeviceInfo<D>::SystemFirmwareVersion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo)->get_SystemFirmwareVersion(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_System_Profile_SystemManufacturers_ISystemSupportInfoStatics<D>::LocalSystemEdition() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics)->get_LocalSystemEdition(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Profile::SystemManufacturers::OemSupportInfo consume_Windows_System_Profile_SystemManufacturers_ISystemSupportInfoStatics<D>::OemSupportInfo() const
{
    Windows::System::Profile::SystemManufacturers::OemSupportInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics)->get_OemSupportInfo(put_abi(value)));
    return value;
}

template <typename D> Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo consume_Windows_System_Profile_SystemManufacturers_ISystemSupportInfoStatics2<D>::LocalDeviceInfo() const
{
    Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics2)->get_LocalDeviceInfo(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::System::Profile::SystemManufacturers::IOemSupportInfo> : produce_base<D, Windows::System::Profile::SystemManufacturers::IOemSupportInfo>
{
    int32_t WINRT_CALL get_SupportLink(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportLink, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().SupportLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportAppLink(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportAppLink, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().SupportAppLink());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportProvider(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportProvider, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SupportProvider());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::SystemManufacturers::ISmbiosInformationStatics> : produce_base<D, Windows::System::Profile::SystemManufacturers::ISmbiosInformationStatics>
{
    int32_t WINRT_CALL get_SerialNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SerialNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SerialNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo> : produce_base<D, Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo>
{
    int32_t WINRT_CALL get_OperatingSystem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OperatingSystem, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().OperatingSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FriendlyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FriendlyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FriendlyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemManufacturer(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemManufacturer, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemManufacturer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemProductName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemProductName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemProductName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemSku(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemSku, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemSku());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemHardwareVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemHardwareVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemHardwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemFirmwareVersion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemFirmwareVersion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SystemFirmwareVersion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics> : produce_base<D, Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics>
{
    int32_t WINRT_CALL get_LocalSystemEdition(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalSystemEdition, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().LocalSystemEdition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OemSupportInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OemSupportInfo, WINRT_WRAP(Windows::System::Profile::SystemManufacturers::OemSupportInfo));
            *value = detach_from<Windows::System::Profile::SystemManufacturers::OemSupportInfo>(this->shim().OemSupportInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics2> : produce_base<D, Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics2>
{
    int32_t WINRT_CALL get_LocalDeviceInfo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalDeviceInfo, WINRT_WRAP(Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo));
            *value = detach_from<Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo>(this->shim().LocalDeviceInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::System::Profile::SystemManufacturers {

inline hstring SmbiosInformation::SerialNumber()
{
    return impl::call_factory<SmbiosInformation, Windows::System::Profile::SystemManufacturers::ISmbiosInformationStatics>([&](auto&& f) { return f.SerialNumber(); });
}

inline hstring SystemSupportInfo::LocalSystemEdition()
{
    return impl::call_factory<SystemSupportInfo, Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics>([&](auto&& f) { return f.LocalSystemEdition(); });
}

inline Windows::System::Profile::SystemManufacturers::OemSupportInfo SystemSupportInfo::OemSupportInfo()
{
    return impl::call_factory<SystemSupportInfo, Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics>([&](auto&& f) { return f.OemSupportInfo(); });
}

inline Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo SystemSupportInfo::LocalDeviceInfo()
{
    return impl::call_factory<SystemSupportInfo, Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics2>([&](auto&& f) { return f.LocalDeviceInfo(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::IOemSupportInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemManufacturers::IOemSupportInfo> {};
template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::ISmbiosInformationStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemManufacturers::ISmbiosInformationStatics> {};
template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportDeviceInfo> {};
template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics> {};
template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics2> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemManufacturers::ISystemSupportInfoStatics2> {};
template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::OemSupportInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemManufacturers::OemSupportInfo> {};
template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::SmbiosInformation> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemManufacturers::SmbiosInformation> {};
template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemManufacturers::SystemSupportDeviceInfo> {};
template<> struct hash<winrt::Windows::System::Profile::SystemManufacturers::SystemSupportInfo> : winrt::impl::hash_base<winrt::Windows::System::Profile::SystemManufacturers::SystemSupportInfo> {};

}
