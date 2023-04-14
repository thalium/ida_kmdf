// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Appointments.2.h"
#include "winrt/impl/Windows.ApplicationModel.Appointments.AppointmentsProvider.2.h"
#include "winrt/Windows.ApplicationModel.Appointments.h"

namespace winrt::impl {

template <typename D> Windows::ApplicationModel::Appointments::Appointment consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::AppointmentInformation() const
{
    Windows::ApplicationModel::Appointments::Appointment value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->get_AppointmentInformation(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::SourcePackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->get_SourcePackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::ReportCompleted(param::hstring const& itemId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->ReportCompleted(get_abi(itemId)));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::ReportCanceled() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->ReportCanceled());
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::ReportError(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->ReportError(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::DismissUI() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->DismissUI());
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAppointmentsProviderLaunchActionVerbsStatics<D>::AddAppointment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics)->get_AddAppointment(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAppointmentsProviderLaunchActionVerbsStatics<D>::ReplaceAppointment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics)->get_ReplaceAppointment(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAppointmentsProviderLaunchActionVerbsStatics<D>::RemoveAppointment() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics)->get_RemoveAppointment(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAppointmentsProviderLaunchActionVerbsStatics<D>::ShowTimeFrame() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics)->get_ShowTimeFrame(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAppointmentsProviderLaunchActionVerbsStatics2<D>::ShowAppointmentDetails() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics2)->get_ShowAppointmentDetails(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::AppointmentId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->get_AppointmentId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::InstanceStartDate() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->get_InstanceStartDate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::SourcePackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->get_SourcePackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::ReportCompleted() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->ReportCompleted());
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::ReportCanceled() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->ReportCanceled());
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::ReportError(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->ReportError(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::DismissUI() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->DismissUI());
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::AppointmentId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->get_AppointmentId(put_abi(value)));
    return value;
}

template <typename D> Windows::ApplicationModel::Appointments::Appointment consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::AppointmentInformation() const
{
    Windows::ApplicationModel::Appointments::Appointment value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->get_AppointmentInformation(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IReference<Windows::Foundation::DateTime> consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::InstanceStartDate() const
{
    Windows::Foundation::IReference<Windows::Foundation::DateTime> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->get_InstanceStartDate(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::SourcePackageFamilyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->get_SourcePackageFamilyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::ReportCompleted(param::hstring const& itemId) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->ReportCompleted(get_abi(itemId)));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::ReportCanceled() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->ReportCanceled());
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::ReportError(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->ReportError(get_abi(value)));
}

template <typename D> void consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::DismissUI() const
{
    check_hresult(WINRT_SHIM(Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->DismissUI());
}

template <typename D>
struct produce<D, Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation> : produce_base<D, Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation>
{
    int32_t WINRT_CALL get_AppointmentInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentInformation, WINRT_WRAP(Windows::ApplicationModel::Appointments::Appointment));
            *value = detach_from<Windows::ApplicationModel::Appointments::Appointment>(this->shim().AppointmentInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourcePackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SourcePackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompleted(void* itemId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void), hstring const&);
            this->shim().ReportCompleted(*reinterpret_cast<hstring const*>(&itemId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCanceled() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCanceled, WINRT_WRAP(void));
            this->shim().ReportCanceled();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportError(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportError, WINRT_WRAP(void), hstring const&);
            this->shim().ReportError(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DismissUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DismissUI, WINRT_WRAP(void));
            this->shim().DismissUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics> : produce_base<D, Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics>
{
    int32_t WINRT_CALL get_AddAppointment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddAppointment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AddAppointment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReplaceAppointment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReplaceAppointment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ReplaceAppointment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemoveAppointment(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveAppointment, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RemoveAppointment());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShowTimeFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowTimeFrame, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ShowTimeFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics2> : produce_base<D, Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics2>
{
    int32_t WINRT_CALL get_ShowAppointmentDetails(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowAppointmentDetails, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ShowAppointmentDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation> : produce_base<D, Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation>
{
    int32_t WINRT_CALL get_AppointmentId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstanceStartDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstanceStartDate, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().InstanceStartDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourcePackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SourcePackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompleted() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void));
            this->shim().ReportCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCanceled() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCanceled, WINRT_WRAP(void));
            this->shim().ReportCanceled();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportError(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportError, WINRT_WRAP(void), hstring const&);
            this->shim().ReportError(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DismissUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DismissUI, WINRT_WRAP(void));
            this->shim().DismissUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation> : produce_base<D, Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation>
{
    int32_t WINRT_CALL get_AppointmentId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AppointmentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppointmentInformation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppointmentInformation, WINRT_WRAP(Windows::ApplicationModel::Appointments::Appointment));
            *value = detach_from<Windows::ApplicationModel::Appointments::Appointment>(this->shim().AppointmentInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InstanceStartDate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InstanceStartDate, WINRT_WRAP(Windows::Foundation::IReference<Windows::Foundation::DateTime>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Foundation::DateTime>>(this->shim().InstanceStartDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SourcePackageFamilyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourcePackageFamilyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SourcePackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompleted(void* itemId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompleted, WINRT_WRAP(void), hstring const&);
            this->shim().ReportCompleted(*reinterpret_cast<hstring const*>(&itemId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCanceled() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCanceled, WINRT_WRAP(void));
            this->shim().ReportCanceled();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportError(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportError, WINRT_WRAP(void), hstring const&);
            this->shim().ReportError(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DismissUI() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DismissUI, WINRT_WRAP(void));
            this->shim().DismissUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider {

inline hstring AppointmentsProviderLaunchActionVerbs::AddAppointment()
{
    return impl::call_factory<AppointmentsProviderLaunchActionVerbs, Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics>([&](auto&& f) { return f.AddAppointment(); });
}

inline hstring AppointmentsProviderLaunchActionVerbs::ReplaceAppointment()
{
    return impl::call_factory<AppointmentsProviderLaunchActionVerbs, Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics>([&](auto&& f) { return f.ReplaceAppointment(); });
}

inline hstring AppointmentsProviderLaunchActionVerbs::RemoveAppointment()
{
    return impl::call_factory<AppointmentsProviderLaunchActionVerbs, Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics>([&](auto&& f) { return f.RemoveAppointment(); });
}

inline hstring AppointmentsProviderLaunchActionVerbs::ShowTimeFrame()
{
    return impl::call_factory<AppointmentsProviderLaunchActionVerbs, Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics>([&](auto&& f) { return f.ShowTimeFrame(); });
}

inline hstring AppointmentsProviderLaunchActionVerbs::ShowAppointmentDetails()
{
    return impl::call_factory<AppointmentsProviderLaunchActionVerbs, Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics2>([&](auto&& f) { return f.ShowAppointmentDetails(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics2> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics2> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::AddAppointmentOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::AddAppointmentOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::AppointmentsProviderLaunchActionVerbs> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::AppointmentsProviderLaunchActionVerbs> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::RemoveAppointmentOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::RemoveAppointmentOperation> {};
template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::ReplaceAppointmentOperation> : winrt::impl::hash_base<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::ReplaceAppointmentOperation> {};

}
