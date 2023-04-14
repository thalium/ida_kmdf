// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.Enumeration.0.h"
#include "winrt/impl/Windows.Graphics.Imaging.0.h"
#include "winrt/impl/Windows.Media.0.h"
#include "winrt/impl/Windows.Media.Devices.Core.0.h"
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Devices.Perception.0.h"

WINRT_EXPORT namespace winrt::Windows::Devices::Perception {

struct WINRT_EBO IKnownCameraIntrinsicsPropertiesStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKnownCameraIntrinsicsPropertiesStatics>
{
    IKnownCameraIntrinsicsPropertiesStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKnownPerceptionColorFrameSourcePropertiesStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKnownPerceptionColorFrameSourcePropertiesStatics>
{
    IKnownPerceptionColorFrameSourcePropertiesStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKnownPerceptionDepthFrameSourcePropertiesStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKnownPerceptionDepthFrameSourcePropertiesStatics>
{
    IKnownPerceptionDepthFrameSourcePropertiesStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKnownPerceptionFrameSourcePropertiesStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKnownPerceptionFrameSourcePropertiesStatics>
{
    IKnownPerceptionFrameSourcePropertiesStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKnownPerceptionFrameSourcePropertiesStatics2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKnownPerceptionFrameSourcePropertiesStatics2>
{
    IKnownPerceptionFrameSourcePropertiesStatics2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKnownPerceptionInfraredFrameSourcePropertiesStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKnownPerceptionInfraredFrameSourcePropertiesStatics>
{
    IKnownPerceptionInfraredFrameSourcePropertiesStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKnownPerceptionVideoFrameSourcePropertiesStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKnownPerceptionVideoFrameSourcePropertiesStatics>
{
    IKnownPerceptionVideoFrameSourcePropertiesStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IKnownPerceptionVideoProfilePropertiesStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IKnownPerceptionVideoProfilePropertiesStatics>
{
    IKnownPerceptionVideoProfilePropertiesStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionColorFrame :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionColorFrame>,
    impl::require<IPerceptionColorFrame, Windows::Foundation::IClosable>
{
    IPerceptionColorFrame(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionColorFrameArrivedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionColorFrameArrivedEventArgs>
{
    IPerceptionColorFrameArrivedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionColorFrameReader :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionColorFrameReader>,
    impl::require<IPerceptionColorFrameReader, Windows::Foundation::IClosable>
{
    IPerceptionColorFrameReader(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionColorFrameSource :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionColorFrameSource>
{
    IPerceptionColorFrameSource(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionColorFrameSource2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionColorFrameSource2>
{
    IPerceptionColorFrameSource2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionColorFrameSourceAddedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionColorFrameSourceAddedEventArgs>
{
    IPerceptionColorFrameSourceAddedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionColorFrameSourceRemovedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionColorFrameSourceRemovedEventArgs>
{
    IPerceptionColorFrameSourceRemovedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionColorFrameSourceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionColorFrameSourceStatics>
{
    IPerceptionColorFrameSourceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionColorFrameSourceWatcher :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionColorFrameSourceWatcher>
{
    IPerceptionColorFrameSourceWatcher(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionControlSession :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionControlSession>,
    impl::require<IPerceptionControlSession, Windows::Foundation::IClosable>
{
    IPerceptionControlSession(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionDepthCorrelatedCameraIntrinsics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionDepthCorrelatedCameraIntrinsics>
{
    IPerceptionDepthCorrelatedCameraIntrinsics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionDepthCorrelatedCoordinateMapper :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionDepthCorrelatedCoordinateMapper>
{
    IPerceptionDepthCorrelatedCoordinateMapper(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionDepthFrame :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionDepthFrame>,
    impl::require<IPerceptionDepthFrame, Windows::Foundation::IClosable>
{
    IPerceptionDepthFrame(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionDepthFrameArrivedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionDepthFrameArrivedEventArgs>
{
    IPerceptionDepthFrameArrivedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionDepthFrameReader :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionDepthFrameReader>,
    impl::require<IPerceptionDepthFrameReader, Windows::Foundation::IClosable>
{
    IPerceptionDepthFrameReader(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionDepthFrameSource :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionDepthFrameSource>
{
    IPerceptionDepthFrameSource(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionDepthFrameSource2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionDepthFrameSource2>
{
    IPerceptionDepthFrameSource2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionDepthFrameSourceAddedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionDepthFrameSourceAddedEventArgs>
{
    IPerceptionDepthFrameSourceAddedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionDepthFrameSourceRemovedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionDepthFrameSourceRemovedEventArgs>
{
    IPerceptionDepthFrameSourceRemovedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionDepthFrameSourceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionDepthFrameSourceStatics>
{
    IPerceptionDepthFrameSourceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionDepthFrameSourceWatcher :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionDepthFrameSourceWatcher>
{
    IPerceptionDepthFrameSourceWatcher(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionFrameSourcePropertiesChangedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionFrameSourcePropertiesChangedEventArgs>
{
    IPerceptionFrameSourcePropertiesChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionFrameSourcePropertyChangeResult :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionFrameSourcePropertyChangeResult>
{
    IPerceptionFrameSourcePropertyChangeResult(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionInfraredFrame :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionInfraredFrame>,
    impl::require<IPerceptionInfraredFrame, Windows::Foundation::IClosable>
{
    IPerceptionInfraredFrame(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionInfraredFrameArrivedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionInfraredFrameArrivedEventArgs>
{
    IPerceptionInfraredFrameArrivedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionInfraredFrameReader :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionInfraredFrameReader>,
    impl::require<IPerceptionInfraredFrameReader, Windows::Foundation::IClosable>
{
    IPerceptionInfraredFrameReader(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionInfraredFrameSource :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionInfraredFrameSource>
{
    IPerceptionInfraredFrameSource(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionInfraredFrameSource2 :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionInfraredFrameSource2>
{
    IPerceptionInfraredFrameSource2(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionInfraredFrameSourceAddedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionInfraredFrameSourceAddedEventArgs>
{
    IPerceptionInfraredFrameSourceAddedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionInfraredFrameSourceRemovedEventArgs :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionInfraredFrameSourceRemovedEventArgs>
{
    IPerceptionInfraredFrameSourceRemovedEventArgs(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionInfraredFrameSourceStatics :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionInfraredFrameSourceStatics>
{
    IPerceptionInfraredFrameSourceStatics(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionInfraredFrameSourceWatcher :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionInfraredFrameSourceWatcher>
{
    IPerceptionInfraredFrameSourceWatcher(std::nullptr_t = nullptr) noexcept {}
};

struct WINRT_EBO IPerceptionVideoProfile :
    Windows::Foundation::IInspectable,
    impl::consume_t<IPerceptionVideoProfile>
{
    IPerceptionVideoProfile(std::nullptr_t = nullptr) noexcept {}
};

}
