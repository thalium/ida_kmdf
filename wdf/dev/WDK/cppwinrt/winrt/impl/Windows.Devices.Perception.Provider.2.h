// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Perception.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Graphics.Imaging.1.h"
#include "winrt/impl/Windows.Media.1.h"
#include "winrt/impl/Windows.Devices.Perception.Provider.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Perception::Provider {

struct PerceptionStartFaceAuthenticationHandler : Windows::Foundation::IUnknown
{
    PerceptionStartFaceAuthenticationHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> PerceptionStartFaceAuthenticationHandler(L lambda);
    template <typename F> PerceptionStartFaceAuthenticationHandler(F* function);
    template <typename O, typename M> PerceptionStartFaceAuthenticationHandler(O* object, M method);
    template <typename O, typename M> PerceptionStartFaceAuthenticationHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> PerceptionStartFaceAuthenticationHandler(weak_ref<O>&& object, M method);
    bool operator()(Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& sender) const;
};

struct PerceptionStopFaceAuthenticationHandler : Windows::Foundation::IUnknown
{
    PerceptionStopFaceAuthenticationHandler(std::nullptr_t = nullptr) noexcept {}
    template <typename L> PerceptionStopFaceAuthenticationHandler(L lambda);
    template <typename F> PerceptionStopFaceAuthenticationHandler(F* function);
    template <typename O, typename M> PerceptionStopFaceAuthenticationHandler(O* object, M method);
    template <typename O, typename M> PerceptionStopFaceAuthenticationHandler(com_ptr<O>&& object, M method);
    template <typename O, typename M> PerceptionStopFaceAuthenticationHandler(weak_ref<O>&& object, M method);
    void operator()(Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& sender) const;
};

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::Perception::Provider {

struct KnownPerceptionFrameKind
{
    KnownPerceptionFrameKind() = delete;
    static hstring Color();
    static hstring Depth();
    static hstring Infrared();
};

struct WINRT_EBO PerceptionControlGroup :
    Windows::Devices::Perception::Provider::IPerceptionControlGroup
{
    PerceptionControlGroup(std::nullptr_t) noexcept {}
    PerceptionControlGroup(param::iterable<hstring> const& ids);
};

struct WINRT_EBO PerceptionCorrelation :
    Windows::Devices::Perception::Provider::IPerceptionCorrelation
{
    PerceptionCorrelation(std::nullptr_t) noexcept {}
    PerceptionCorrelation(param::hstring const& targetId, Windows::Foundation::Numerics::float3 const& position, Windows::Foundation::Numerics::quaternion const& orientation);
};

struct WINRT_EBO PerceptionCorrelationGroup :
    Windows::Devices::Perception::Provider::IPerceptionCorrelationGroup
{
    PerceptionCorrelationGroup(std::nullptr_t) noexcept {}
    PerceptionCorrelationGroup(param::iterable<Windows::Devices::Perception::Provider::PerceptionCorrelation> const& relativeLocations);
};

struct WINRT_EBO PerceptionFaceAuthenticationGroup :
    Windows::Devices::Perception::Provider::IPerceptionFaceAuthenticationGroup
{
    PerceptionFaceAuthenticationGroup(std::nullptr_t) noexcept {}
    PerceptionFaceAuthenticationGroup(param::iterable<hstring> const& ids, Windows::Devices::Perception::Provider::PerceptionStartFaceAuthenticationHandler const& startHandler, Windows::Devices::Perception::Provider::PerceptionStopFaceAuthenticationHandler const& stopHandler);
};

struct WINRT_EBO PerceptionFrame :
    Windows::Devices::Perception::Provider::IPerceptionFrame
{
    PerceptionFrame(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PerceptionFrameProviderInfo :
    Windows::Devices::Perception::Provider::IPerceptionFrameProviderInfo
{
    PerceptionFrameProviderInfo(std::nullptr_t) noexcept {}
    PerceptionFrameProviderInfo();
};

struct PerceptionFrameProviderManagerService
{
    PerceptionFrameProviderManagerService() = delete;
    static void RegisterFrameProviderInfo(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo);
    static void UnregisterFrameProviderInfo(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFrameProviderInfo const& frameProviderInfo);
    static void RegisterFaceAuthenticationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup);
    static void UnregisterFaceAuthenticationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionFaceAuthenticationGroup const& faceAuthenticationGroup);
    static void RegisterControlGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup);
    static void UnregisterControlGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionControlGroup const& controlGroup);
    static void RegisterCorrelationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup);
    static void UnregisterCorrelationGroup(Windows::Devices::Perception::Provider::IPerceptionFrameProviderManager const& manager, Windows::Devices::Perception::Provider::PerceptionCorrelationGroup const& correlationGroup);
    static void UpdateAvailabilityForProvider(Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, bool available);
    static void PublishFrameForProvider(Windows::Devices::Perception::Provider::IPerceptionFrameProvider const& provider, Windows::Devices::Perception::Provider::PerceptionFrame const& frame);
};

struct WINRT_EBO PerceptionPropertyChangeRequest :
    Windows::Devices::Perception::Provider::IPerceptionPropertyChangeRequest
{
    PerceptionPropertyChangeRequest(std::nullptr_t) noexcept {}
};

struct WINRT_EBO PerceptionVideoFrameAllocator :
    Windows::Devices::Perception::Provider::IPerceptionVideoFrameAllocator
{
    PerceptionVideoFrameAllocator(std::nullptr_t) noexcept {}
    PerceptionVideoFrameAllocator(uint32_t maxOutstandingFrameCountForWrite, Windows::Graphics::Imaging::BitmapPixelFormat const& format, Windows::Foundation::Size const& resolution, Windows::Graphics::Imaging::BitmapAlphaMode const& alpha);
};

}
