// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Perception.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Devices.Perception.Provider.2.h"
#include "winrt/Windows.Devices.Perception.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_Devices_Perception_Provider_IKnownPerceptionFrameKindStatics<D>::Color() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics)->get_Color(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Perception_Provider_IKnownPerceptionFrameKindStatics<D>::Depth() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics)->get_Depth(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_Perception_Provider_IKnownPerceptionFrameKindStatics<D>::Infrared() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics)->get_Infrared(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Devices_Perception_Provider_IPerceptionControlGroup<D>::FrameProviderIds() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionControlGroup)->get_FrameProviderIds(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Perception::Provider::PerceptionControlGroup consume_Windows_Devices_Perception_Provider_IPerceptionControlGroupFactory<D>::Create(param::iterable<hstring> const& ids) const
{
    Windows::Devices::Perception::Provider::PerceptionControlGroup result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory)->Create(get_abi(ids), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_Perception_Provider_IPerceptionCorrelation<D>::TargetId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionCorrelation)->get_TargetId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_Devices_Perception_Provider_IPerceptionCorrelation<D>::Position() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionCorrelation)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Numerics::quaternion consume_Windows_Devices_Perception_Provider_IPerceptionCorrelation<D>::Orientation() const
{
    Windows::Foundation::Numerics::quaternion value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionCorrelation)->get_Orientation(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Perception::Provider::PerceptionCorrelation consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationFactory<D>::Create(param::hstring const& targetId, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::quaternion const& orientation) const
{
    Windows::Devices::Perception::Provider::PerceptionCorrelation result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory)->Create(get_abi(targetId), get_abi(position), get_abi(orientation), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Devices::Perception::Provider::PerceptionCorrelation> consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationGroup<D>::RelativeLocations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Devices::Perception::Provider::PerceptionCorrelation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup)->get_RelativeLocations(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Perception::Provider::PerceptionCorrelationGroup consume_Windows_Devices_Perception_Provider_IPerceptionCorrelationGroupFactory<D>::Create(param::iterable<Windows::Devices::Perception::Provider::PerceptionCorrelation> const& relativeLocations) const
{
    Windows::Devices::Perception::Provider::PerceptionCorrelationGroup result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory)->Create(get_abi(relativeLocations), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Devices_Perception_Provider_IPerceptionFaceAuthenticationGroup<D>::FrameProviderIds() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup)->get_FrameProviderIds(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup consume_Windows_Devices_Perception_Provider_IPerceptionFaceAuthenticationGroupFactory<D>::Create(param::iterable<hstring> const& ids, Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler const& startHandler, Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler const& stopHandler) const
{
    Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory)->Create(get_abi(ids), get_abi(startHandler), get_abi(stopHandler), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Devices_Perception_Provider_IPerceptionFrame<D>::RelativeTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrame)->get_RelativeTime(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrame<D>::RelativeTime(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrame)->put_RelativeTime(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::ValueSet consume_Windows_Devices_Perception_Provider_IPerceptionFrame<D>::Properties() const
{
    Windows::Foundation::Collections::ValueSet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrame)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IMemoryBuffer consume_Windows_Devices_Perception_Provider_IPerceptionFrame<D>::FrameData() const
{
    Windows::Foundation::IMemoryBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrame)->get_FrameData(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::FrameProviderInfo() const
{
    Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->get_FrameProviderInfo(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::Available() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->get_Available(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::Properties() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->Start());
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->Stop());
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProvider<D>::SetProperty(Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProvider)->SetProperty(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::Id(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->put_Id(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::DeviceKind() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->get_DeviceKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::DeviceKind(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->put_DeviceKind(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::FrameKind() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->get_FrameKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::FrameKind(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->put_FrameKind(get_abi(value)));
}

template <typename D> bool consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::Hidden() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->get_Hidden(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderInfo<D>::Hidden(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo)->put_Hidden(value));
}

template <typename D> Windows::Devices::Perception::Provider::IPerceptionFrameProvider consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManager<D>::GetFrameProvider(Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo) const
{
    Windows::Devices::Perception::Provider::IPerceptionFrameProvider result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager)->GetFrameProvider(get_abi(frameProviderInfo), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::RegisterFrameProviderInfo(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->RegisterFrameProviderInfo(get_abi(manager), get_abi(frameProviderInfo)));
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::UnregisterFrameProviderInfo(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->UnregisterFrameProviderInfo(get_abi(manager), get_abi(frameProviderInfo)));
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::RegisterFaceAuthenticationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->RegisterFaceAuthenticationGroup(get_abi(manager), get_abi(faceAuthenticationGroup)));
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::UnregisterFaceAuthenticationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->UnregisterFaceAuthenticationGroup(get_abi(manager), get_abi(faceAuthenticationGroup)));
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::RegisterControlGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->RegisterControlGroup(get_abi(manager), get_abi(controlGroup)));
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::UnregisterControlGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->UnregisterControlGroup(get_abi(manager), get_abi(controlGroup)));
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::RegisterCorrelationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->RegisterCorrelationGroup(get_abi(manager), get_abi(correlationGroup)));
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::UnregisterCorrelationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->UnregisterCorrelationGroup(get_abi(manager), get_abi(correlationGroup)));
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::UpdateAvailabilityForProvider(Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, bool available) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->UpdateAvailabilityForProvider(get_abi(provider), available));
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionFrameProviderManagerServiceStatics<D>::PublishFrameForProvider(Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, Windows::Devices::Perception::Provider::PerceptionFrame const& frame) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics)->PublishFrameForProvider(get_abi(provider), get_abi(frame)));
}

template <typename D> hstring consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest<D>::Value() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest)->get_Value(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest<D>::Status() const
{
    Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus value{};
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest<D>::Status(Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest)->put_Status(get_abi(value)));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_Perception_Provider_IPerceptionPropertyChangeRequest<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Devices::Perception::Provider::PerceptionFrame consume_Windows_Devices_Perception_Provider_IPerceptionVideoFrameAllocator<D>::AllocateFrame() const
{
    Windows::Devices::Perception::Provider::PerceptionFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator)->AllocateFrame(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Perception::Provider::PerceptionFrame consume_Windows_Devices_Perception_Provider_IPerceptionVideoFrameAllocator<D>::CopyFromVideoFrame(Windows::Media::VideoFrame const& frame) const
{
    Windows::Devices::Perception::Provider::PerceptionFrame value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator)->CopyFromVideoFrame(get_abi(frame), put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator consume_Windows_Devices_Perception_Provider_IPerceptionVideoFrameAllocatorFactory<D>::Create(uint32_t maxOutstandingFrameCountForWrite, Windows::Graphics::Imaging::BitmapPixelFormat const& format, Windows::Foundation::Size const& resolution, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) const
{
    Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory)->Create(maxOutstandingFrameCountForWrite, get_abi(format), get_abi(resolution), get_abi(alpha), put_abi(result)));
    return result;
}

template <> struct delegate<Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, bool* result) noexcept final
        {
            try
            {
                *result = detach_from<bool>((*this)(*reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const*>(&sender)));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const*>(&sender));
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
struct produce<D, Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics> : produce_base<D, Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics>
{
    int32_t WINRT_CALL get_Color(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Depth(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Depth, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Depth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Infrared(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Infrared, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Infrared());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionControlGroup> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionControlGroup>
{
    int32_t WINRT_CALL get_FrameProviderIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameProviderIds, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().FrameProviderIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory>
{
    int32_t WINRT_CALL Create(void* ids, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Perception::Provider::PerceptionControlGroup), Windows::Foundation::Collections::IIterable<hstring> const&);
            *result = detach_from<Windows::Devices::Perception::Provider::PerceptionControlGroup>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&ids)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionCorrelation> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionCorrelation>
{
    int32_t WINRT_CALL get_TargetId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TargetId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Position(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Orientation(Windows::Foundation::Numerics::quaternion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Orientation, WINRT_WRAP(Windows::Foundation::Numerics::quaternion));
            *value = detach_from<Windows::Foundation::Numerics::quaternion>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory>
{
    int32_t WINRT_CALL Create(void* targetId, Windows::Foundation::Numerics::float3 position, Windows::Foundation::Numerics::quaternion orientation, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Perception::Provider::PerceptionCorrelation), hstring const&, Windows::Foundation::Numerics::float3 const&, Windows::Foundation::Numerics::quaternion const&);
            *result = detach_from<Windows::Devices::Perception::Provider::PerceptionCorrelation>(this->shim().Create(*reinterpret_cast<hstring const*>(&targetId), *reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&position), *reinterpret_cast<Windows::Foundation::Numerics::quaternion const*>(&orientation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup>
{
    int32_t WINRT_CALL get_RelativeLocations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeLocations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Devices::Perception::Provider::PerceptionCorrelation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Devices::Perception::Provider::PerceptionCorrelation>>(this->shim().RelativeLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory>
{
    int32_t WINRT_CALL Create(void* relativeLocations, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Perception::Provider::PerceptionCorrelationGroup), Windows::Foundation::Collections::IIterable<Windows::Devices::Perception::Provider::PerceptionCorrelation> const&);
            *result = detach_from<Windows::Devices::Perception::Provider::PerceptionCorrelationGroup>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Perception::Provider::PerceptionCorrelation> const*>(&relativeLocations)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup>
{
    int32_t WINRT_CALL get_FrameProviderIds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameProviderIds, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().FrameProviderIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory>
{
    int32_t WINRT_CALL Create(void* ids, void* startHandler, void* stopHandler, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup), Windows::Foundation::Collections::IIterable<hstring> const&, Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler const&, Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler const&);
            *result = detach_from<Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup>(this->shim().Create(*reinterpret_cast<Windows::Foundation::Collections::IIterable<hstring> const*>(&ids), *reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler const*>(&startHandler), *reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler const*>(&stopHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionFrame> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionFrame>
{
    int32_t WINRT_CALL get_RelativeTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().RelativeTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RelativeTime(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeTime, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().RelativeTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::ValueSet));
            *value = detach_from<Windows::Foundation::Collections::ValueSet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameData, WINRT_WRAP(Windows::Foundation::IMemoryBuffer));
            *value = detach_from<Windows::Foundation::IMemoryBuffer>(this->shim().FrameData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionFrameProvider> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionFrameProvider>
{
    int32_t WINRT_CALL get_FrameProviderInfo(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameProviderInfo, WINRT_WRAP(Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo));
            *result = detach_from<Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo>(this->shim().FrameProviderInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Available(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Available, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Available());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Properties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
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

    int32_t WINRT_CALL SetProperty(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetProperty, WINRT_WRAP(void), Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest const&);
            this->shim().SetProperty(*reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo>
{
    int32_t WINRT_CALL get_Id(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Id(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), hstring const&);
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL put_DisplayName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayName, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DeviceKind(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceKind, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DeviceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DeviceKind(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeviceKind, WINRT_WRAP(void), hstring const&);
            this->shim().DeviceKind(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameKind(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameKind, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FrameKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FrameKind(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameKind, WINRT_WRAP(void), hstring const&);
            this->shim().FrameKind(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hidden(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hidden, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Hidden());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Hidden(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hidden, WINRT_WRAP(void), bool);
            this->shim().Hidden(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager>
{
    int32_t WINRT_CALL GetFrameProvider(void* frameProviderInfo, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetFrameProvider, WINRT_WRAP(Windows::Devices::Perception::Provider::IPerceptionFrameProvider), Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const&);
            *result = detach_from<Windows::Devices::Perception::Provider::IPerceptionFrameProvider>(this->shim().GetFrameProvider(*reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const*>(&frameProviderInfo)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>
{
    int32_t WINRT_CALL RegisterFrameProviderInfo(void* manager, void* frameProviderInfo) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterFrameProviderInfo, WINRT_WRAP(void), Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const&, Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const&);
            this->shim().RegisterFrameProviderInfo(*reinterpret_cast<Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const*>(&frameProviderInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnregisterFrameProviderInfo(void* manager, void* frameProviderInfo) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnregisterFrameProviderInfo, WINRT_WRAP(void), Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const&, Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const&);
            this->shim().UnregisterFrameProviderInfo(*reinterpret_cast<Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const*>(&frameProviderInfo));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterFaceAuthenticationGroup(void* manager, void* faceAuthenticationGroup) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterFaceAuthenticationGroup, WINRT_WRAP(void), Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const&, Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const&);
            this->shim().RegisterFaceAuthenticationGroup(*reinterpret_cast<Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const*>(&faceAuthenticationGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnregisterFaceAuthenticationGroup(void* manager, void* faceAuthenticationGroup) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnregisterFaceAuthenticationGroup, WINRT_WRAP(void), Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const&, Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const&);
            this->shim().UnregisterFaceAuthenticationGroup(*reinterpret_cast<Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const*>(&faceAuthenticationGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterControlGroup(void* manager, void* controlGroup) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterControlGroup, WINRT_WRAP(void), Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const&, Windows::Devices::Perception::Provider::PerceptionControlGroup const&);
            this->shim().RegisterControlGroup(*reinterpret_cast<Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionControlGroup const*>(&controlGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnregisterControlGroup(void* manager, void* controlGroup) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnregisterControlGroup, WINRT_WRAP(void), Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const&, Windows::Devices::Perception::Provider::PerceptionControlGroup const&);
            this->shim().UnregisterControlGroup(*reinterpret_cast<Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionControlGroup const*>(&controlGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RegisterCorrelationGroup(void* manager, void* correlationGroup) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegisterCorrelationGroup, WINRT_WRAP(void), Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const&, Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const&);
            this->shim().RegisterCorrelationGroup(*reinterpret_cast<Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const*>(&correlationGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UnregisterCorrelationGroup(void* manager, void* correlationGroup) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnregisterCorrelationGroup, WINRT_WRAP(void), Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const&, Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const&);
            this->shim().UnregisterCorrelationGroup(*reinterpret_cast<Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const*>(&manager), *reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const*>(&correlationGroup));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateAvailabilityForProvider(void* provider, bool available) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateAvailabilityForProvider, WINRT_WRAP(void), Windows::Devices::Perception::Provider::IPerceptionFrameProvider const&, bool);
            this->shim().UpdateAvailabilityForProvider(*reinterpret_cast<Windows::Devices::Perception::Provider::IPerceptionFrameProvider const*>(&provider), available);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL PublishFrameForProvider(void* provider, void* frame) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PublishFrameForProvider, WINRT_WRAP(void), Windows::Devices::Perception::Provider::IPerceptionFrameProvider const&, Windows::Devices::Perception::Provider::PerceptionFrame const&);
            this->shim().PublishFrameForProvider(*reinterpret_cast<Windows::Devices::Perception::Provider::IPerceptionFrameProvider const*>(&provider), *reinterpret_cast<Windows::Devices::Perception::Provider::PerceptionFrame const*>(&frame));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest>
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

    int32_t WINRT_CALL get_Value(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus));
            *value = detach_from<Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Status(Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(void), Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus const&);
            this->shim().Status(*reinterpret_cast<Windows::Devices::Perception::PerceptionFrameSourcePropertyChangeStatus const*>(&value));
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
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator>
{
    int32_t WINRT_CALL AllocateFrame(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllocateFrame, WINRT_WRAP(Windows::Devices::Perception::Provider::PerceptionFrame));
            *value = detach_from<Windows::Devices::Perception::Provider::PerceptionFrame>(this->shim().AllocateFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CopyFromVideoFrame(void* frame, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CopyFromVideoFrame, WINRT_WRAP(Windows::Devices::Perception::Provider::PerceptionFrame), Windows::Media::VideoFrame const&);
            *value = detach_from<Windows::Devices::Perception::Provider::PerceptionFrame>(this->shim().CopyFromVideoFrame(*reinterpret_cast<Windows::Media::VideoFrame const*>(&frame)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory> : produce_base<D, Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory>
{
    int32_t WINRT_CALL Create(uint32_t maxOutstandingFrameCountForWrite, Windows::Graphics::Imaging::BitmapPixelFormat format, Windows::Foundation::Size resolution, Windows::Graphics::Imaging::BitmapAlphaMode alpha, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator), uint32_t, Windows::Graphics::Imaging::BitmapPixelFormat const&, Windows::Foundation::Size const&, Windows::Graphics::Imaging::BitmapAlphaMode const&);
            *result = detach_from<Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator>(this->shim().Create(maxOutstandingFrameCountForWrite, *reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&format), *reinterpret_cast<Windows::Foundation::Size const*>(&resolution), *reinterpret_cast<Windows::Graphics::Imaging::BitmapAlphaMode const*>(&alpha)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::Perception::Provider {

inline hstring KnownPerceptionFrameKind::Color()
{
    return impl::call_factory<KnownPerceptionFrameKind, Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics>([&](auto&& f) { return f.Color(); });
}

inline hstring KnownPerceptionFrameKind::Depth()
{
    return impl::call_factory<KnownPerceptionFrameKind, Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics>([&](auto&& f) { return f.Depth(); });
}

inline hstring KnownPerceptionFrameKind::Infrared()
{
    return impl::call_factory<KnownPerceptionFrameKind, Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics>([&](auto&& f) { return f.Infrared(); });
}

inline PerceptionControlGroup::PerceptionControlGroup(param::iterable<hstring> const& ids) :
    PerceptionControlGroup(impl::call_factory<PerceptionControlGroup, Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory>([&](auto&& f) { return f.Create(ids); }))
{}

inline PerceptionCorrelation::PerceptionCorrelation(param::hstring const& targetId, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::quaternion const& orientation) :
    PerceptionCorrelation(impl::call_factory<PerceptionCorrelation, Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory>([&](auto&& f) { return f.Create(targetId, position, orientation); }))
{}

inline PerceptionCorrelationGroup::PerceptionCorrelationGroup(param::iterable<Windows::Devices::Perception::Provider::PerceptionCorrelation> const& relativeLocations) :
    PerceptionCorrelationGroup(impl::call_factory<PerceptionCorrelationGroup, Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory>([&](auto&& f) { return f.Create(relativeLocations); }))
{}

inline PerceptionFaceAuthenticationGroup::PerceptionFaceAuthenticationGroup(param::iterable<hstring> const& ids, Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler const& startHandler, Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler const& stopHandler) :
    PerceptionFaceAuthenticationGroup(impl::call_factory<PerceptionFaceAuthenticationGroup, Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory>([&](auto&& f) { return f.Create(ids, startHandler, stopHandler); }))
{}

inline PerceptionFrameProviderInfo::PerceptionFrameProviderInfo() :
    PerceptionFrameProviderInfo(impl::call_factory<PerceptionFrameProviderInfo>([](auto&& f) { return f.template ActivateInstance<PerceptionFrameProviderInfo>(); }))
{}

inline void PerceptionFrameProviderManagerService::RegisterFrameProviderInfo(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo)
{
    impl::call_factory<PerceptionFrameProviderManagerService, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>([&](auto&& f) { return f.RegisterFrameProviderInfo(manager, frameProviderInfo); });
}

inline void PerceptionFrameProviderManagerService::UnregisterFrameProviderInfo(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo)
{
    impl::call_factory<PerceptionFrameProviderManagerService, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>([&](auto&& f) { return f.UnregisterFrameProviderInfo(manager, frameProviderInfo); });
}

inline void PerceptionFrameProviderManagerService::RegisterFaceAuthenticationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup)
{
    impl::call_factory<PerceptionFrameProviderManagerService, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>([&](auto&& f) { return f.RegisterFaceAuthenticationGroup(manager, faceAuthenticationGroup); });
}

inline void PerceptionFrameProviderManagerService::UnregisterFaceAuthenticationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup)
{
    impl::call_factory<PerceptionFrameProviderManagerService, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>([&](auto&& f) { return f.UnregisterFaceAuthenticationGroup(manager, faceAuthenticationGroup); });
}

inline void PerceptionFrameProviderManagerService::RegisterControlGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup)
{
    impl::call_factory<PerceptionFrameProviderManagerService, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>([&](auto&& f) { return f.RegisterControlGroup(manager, controlGroup); });
}

inline void PerceptionFrameProviderManagerService::UnregisterControlGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup)
{
    impl::call_factory<PerceptionFrameProviderManagerService, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>([&](auto&& f) { return f.UnregisterControlGroup(manager, controlGroup); });
}

inline void PerceptionFrameProviderManagerService::RegisterCorrelationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup)
{
    impl::call_factory<PerceptionFrameProviderManagerService, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>([&](auto&& f) { return f.RegisterCorrelationGroup(manager, correlationGroup); });
}

inline void PerceptionFrameProviderManagerService::UnregisterCorrelationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup)
{
    impl::call_factory<PerceptionFrameProviderManagerService, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>([&](auto&& f) { return f.UnregisterCorrelationGroup(manager, correlationGroup); });
}

inline void PerceptionFrameProviderManagerService::UpdateAvailabilityForProvider(Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, bool available)
{
    impl::call_factory<PerceptionFrameProviderManagerService, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>([&](auto&& f) { return f.UpdateAvailabilityForProvider(provider, available); });
}

inline void PerceptionFrameProviderManagerService::PublishFrameForProvider(Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, Windows::Devices::Perception::Provider::PerceptionFrame const& frame)
{
    impl::call_factory<PerceptionFrameProviderManagerService, Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics>([&](auto&& f) { return f.PublishFrameForProvider(provider, frame); });
}

inline PerceptionVideoFrameAllocator::PerceptionVideoFrameAllocator(uint32_t maxOutstandingFrameCountForWrite, Windows::Graphics::Imaging::BitmapPixelFormat const& format, Windows::Foundation::Size const& resolution, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha) :
    PerceptionVideoFrameAllocator(impl::call_factory<PerceptionVideoFrameAllocator, Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory>([&](auto&& f) { return f.Create(maxOutstandingFrameCountForWrite, format, resolution, alpha); }))
{}

template <typename L> PerceptionStartFaceAuthenticationHandler::PerceptionStartFaceAuthenticationHandler(L handler) :
    PerceptionStartFaceAuthenticationHandler(impl::make_delegate<PerceptionStartFaceAuthenticationHandler>(std::forward<L>(handler)))
{}

template <typename F> PerceptionStartFaceAuthenticationHandler::PerceptionStartFaceAuthenticationHandler(F* handler) :
    PerceptionStartFaceAuthenticationHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> PerceptionStartFaceAuthenticationHandler::PerceptionStartFaceAuthenticationHandler(O* object, M method) :
    PerceptionStartFaceAuthenticationHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> PerceptionStartFaceAuthenticationHandler::PerceptionStartFaceAuthenticationHandler(com_ptr<O>&& object, M method) :
    PerceptionStartFaceAuthenticationHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> PerceptionStartFaceAuthenticationHandler::PerceptionStartFaceAuthenticationHandler(weak_ref<O>&& object, M method) :
    PerceptionStartFaceAuthenticationHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline bool PerceptionStartFaceAuthenticationHandler::operator()(Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& sender) const
{
    bool result{};
    check_hresult((*(impl::abi_t<PerceptionStartFaceAuthenticationHandler>**)this)->Invoke(get_abi(sender), &result));
    return result;
}

template <typename L> PerceptionStopFaceAuthenticationHandler::PerceptionStopFaceAuthenticationHandler(L handler) :
    PerceptionStopFaceAuthenticationHandler(impl::make_delegate<PerceptionStopFaceAuthenticationHandler>(std::forward<L>(handler)))
{}

template <typename F> PerceptionStopFaceAuthenticationHandler::PerceptionStopFaceAuthenticationHandler(F* handler) :
    PerceptionStopFaceAuthenticationHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> PerceptionStopFaceAuthenticationHandler::PerceptionStopFaceAuthenticationHandler(O* object, M method) :
    PerceptionStopFaceAuthenticationHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> PerceptionStopFaceAuthenticationHandler::PerceptionStopFaceAuthenticationHandler(com_ptr<O>&& object, M method) :
    PerceptionStopFaceAuthenticationHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> PerceptionStopFaceAuthenticationHandler::PerceptionStopFaceAuthenticationHandler(weak_ref<O>&& object, M method) :
    PerceptionStopFaceAuthenticationHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void PerceptionStopFaceAuthenticationHandler::operator()(Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& sender) const
{
    check_hresult((*(impl::abi_t<PerceptionStopFaceAuthenticationHandler>**)this)->Invoke(get_abi(sender)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IKnownPerceptionFrameKindStatics> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroup> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionControlGroupFactory> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelation> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationFactory> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionCorrelationGroupFactory> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroupFactory> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFrame> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionFrame> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProvider> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionFrameProviderManagerServiceStatics> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocatorFactory> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::KnownPerceptionFrameKind> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::KnownPerceptionFrameKind> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::PerceptionControlGroup> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelation> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::PerceptionCorrelationGroup> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionFrame> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::PerceptionFrame> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderManagerService> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::PerceptionFrameProviderManagerService> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::PerceptionPropertyChangeRequest> {};
template<> struct hash<winrt::Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator> : winrt::impl::hash_base<winrt::Windows::Devices::Perception::Provider::PerceptionVideoFrameAllocator> {};

}
