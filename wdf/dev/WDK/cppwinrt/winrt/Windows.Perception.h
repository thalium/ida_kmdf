// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Perception.2.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::DateTime consume_Windows_Perception_IPerceptionTimestamp<D>::TargetTime() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Perception::IPerceptionTimestamp)->get_TargetTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Perception_IPerceptionTimestamp<D>::PredictionAmount() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Perception::IPerceptionTimestamp)->get_PredictionAmount(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_Perception_IPerceptionTimestamp2<D>::SystemRelativeTargetTime() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::Perception::IPerceptionTimestamp2)->get_SystemRelativeTargetTime(put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::PerceptionTimestamp consume_Windows_Perception_IPerceptionTimestampHelperStatics<D>::FromHistoricalTargetTime(Windows::Foundation::DateTime const& targetTime) const
{
    Windows::Perception::PerceptionTimestamp value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::IPerceptionTimestampHelperStatics)->FromHistoricalTargetTime(get_abi(targetTime), put_abi(value)));
    return value;
}

template <typename D> Windows::Perception::PerceptionTimestamp consume_Windows_Perception_IPerceptionTimestampHelperStatics2<D>::FromSystemRelativeTargetTime(Windows::Foundation::TimeSpan const& targetTime) const
{
    Windows::Perception::PerceptionTimestamp value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Perception::IPerceptionTimestampHelperStatics2)->FromSystemRelativeTargetTime(get_abi(targetTime), put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Perception::IPerceptionTimestamp> : produce_base<D, Windows::Perception::IPerceptionTimestamp>
{
    int32_t WINRT_CALL get_TargetTime(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetTime, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().TargetTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PredictionAmount(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PredictionAmount, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().PredictionAmount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::IPerceptionTimestamp2> : produce_base<D, Windows::Perception::IPerceptionTimestamp2>
{
    int32_t WINRT_CALL get_SystemRelativeTargetTime(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemRelativeTargetTime, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().SystemRelativeTargetTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::IPerceptionTimestampHelperStatics> : produce_base<D, Windows::Perception::IPerceptionTimestampHelperStatics>
{
    int32_t WINRT_CALL FromHistoricalTargetTime(Windows::Foundation::DateTime targetTime, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromHistoricalTargetTime, WINRT_WRAP(Windows::Perception::PerceptionTimestamp), Windows::Foundation::DateTime const&);
            *value = detach_from<Windows::Perception::PerceptionTimestamp>(this->shim().FromHistoricalTargetTime(*reinterpret_cast<Windows::Foundation::DateTime const*>(&targetTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Perception::IPerceptionTimestampHelperStatics2> : produce_base<D, Windows::Perception::IPerceptionTimestampHelperStatics2>
{
    int32_t WINRT_CALL FromSystemRelativeTargetTime(Windows::Foundation::TimeSpan targetTime, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FromSystemRelativeTargetTime, WINRT_WRAP(Windows::Perception::PerceptionTimestamp), Windows::Foundation::TimeSpan const&);
            *value = detach_from<Windows::Perception::PerceptionTimestamp>(this->shim().FromSystemRelativeTargetTime(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&targetTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Perception {

inline Windows::Perception::PerceptionTimestamp PerceptionTimestampHelper::FromHistoricalTargetTime(Windows::Foundation::DateTime const& targetTime)
{
    return impl::call_factory<PerceptionTimestampHelper, Windows::Perception::IPerceptionTimestampHelperStatics>([&](auto&& f) { return f.FromHistoricalTargetTime(targetTime); });
}

inline Windows::Perception::PerceptionTimestamp PerceptionTimestampHelper::FromSystemRelativeTargetTime(Windows::Foundation::TimeSpan const& targetTime)
{
    return impl::call_factory<PerceptionTimestampHelper, Windows::Perception::IPerceptionTimestampHelperStatics2>([&](auto&& f) { return f.FromSystemRelativeTargetTime(targetTime); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Perception::IPerceptionTimestamp> : winrt::impl::hash_base<winrt::Windows::Perception::IPerceptionTimestamp> {};
template<> struct hash<winrt::Windows::Perception::IPerceptionTimestamp2> : winrt::impl::hash_base<winrt::Windows::Perception::IPerceptionTimestamp2> {};
template<> struct hash<winrt::Windows::Perception::IPerceptionTimestampHelperStatics> : winrt::impl::hash_base<winrt::Windows::Perception::IPerceptionTimestampHelperStatics> {};
template<> struct hash<winrt::Windows::Perception::IPerceptionTimestampHelperStatics2> : winrt::impl::hash_base<winrt::Windows::Perception::IPerceptionTimestampHelperStatics2> {};
template<> struct hash<winrt::Windows::Perception::PerceptionTimestamp> : winrt::impl::hash_base<winrt::Windows::Perception::PerceptionTimestamp> {};
template<> struct hash<winrt::Windows::Perception::PerceptionTimestampHelper> : winrt::impl::hash_base<winrt::Windows::Perception::PerceptionTimestampHelper> {};

}
