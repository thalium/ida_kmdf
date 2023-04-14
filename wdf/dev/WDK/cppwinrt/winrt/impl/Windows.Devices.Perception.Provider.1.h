// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Perception.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Graphics.Imaging.0.h"
#include "winrt/impl/Windows.Media.0.h"
#include "winrt/impl/Windows.Devices.Perception.Provider.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Perception::Provider {

struct WINRT_EBO IKnownPerceptionFrameKindStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKnownPerceptionFrameKindStatics>
{
    IKnownPerceptionFrameKindStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionControlGroup :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionControlGroup>
{
    IPerceptionControlGroup(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionControlGroupFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionControlGroupFactory>
{
    IPerceptionControlGroupFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionCorrelation :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionCorrelation>
{
    IPerceptionCorrelation(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionCorrelationFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionCorrelationFactory>
{
    IPerceptionCorrelationFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionCorrelationGroup :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionCorrelationGroup>
{
    IPerceptionCorrelationGroup(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionCorrelationGroupFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionCorrelationGroupFactory>
{
    IPerceptionCorrelationGroupFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionFaceAuthenticationGroup :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionFaceAuthenticationGroup>
{
    IPerceptionFaceAuthenticationGroup(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionFaceAuthenticationGroupFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionFaceAuthenticationGroupFactory>
{
    IPerceptionFaceAuthenticationGroupFactory(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionFrame :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionFrame>
{
    IPerceptionFrame(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionFrameProvider :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionFrameProvider>,
    impl::require<IPerceptionFrameProvider, Windows::Foundation::IClosable>
{
    IPerceptionFrameProvider(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionFrameProviderInfo :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionFrameProviderInfo>
{
    IPerceptionFrameProviderInfo(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionFrameProviderManager :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionFrameProviderManager>,
    impl::require<IPerceptionFrameProviderManager, Windows::Foundation::IClosable>
{
    IPerceptionFrameProviderManager(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionFrameProviderManagerServiceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionFrameProviderManagerServiceStatics>
{
    IPerceptionFrameProviderManagerServiceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionPropertyChangeRequest :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionPropertyChangeRequest>
{
    IPerceptionPropertyChangeRequest(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionVideoFrameAllocator :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionVideoFrameAllocator>,
    impl::require<IPerceptionVideoFrameAllocator, Windows::Foundation::IClosable>
{
    IPerceptionVideoFrameAllocator(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionVideoFrameAllocatorFactory :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionVideoFrameAllocatorFactory>
{
    IPerceptionVideoFrameAllocatorFactory(std::nullptr_t = nullptr) noexcept {}
};

}
