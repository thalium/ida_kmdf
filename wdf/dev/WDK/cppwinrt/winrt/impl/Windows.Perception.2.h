// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Perception.1.h"

WINRT_EXPORT namespace winrt::Windows::Perception {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Perception {

struct WINRT_EBO PerceptionTimestamp :
    Windows::Perception::IPerceptionTimestamp,
    impl::require<PerceptionTimestamp, Windows::Perception::IPerceptionTimestamp2>
{
    PerceptionTimestamp(std::nullptr_t) noexcept {}
};

struct PerceptionTimestampHelper
{
    PerceptionTimestampHelper() = delete;
    static Windows::Perception::PerceptionTimestamp FromHistoricalTargetTime(Windows::Foundation::DateTime const& targetTime);
    static Windows::Perception::PerceptionTimestamp FromSystemRelativeTargetTime(Windows::Foundation::TimeSpan const& targetTime);
};

}
