// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#include "winrt/impl/Windows.Devices.PointOfService.1.h"
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Graphics.Imaging.1.h"
#include "winrt/impl/Windows.Storage.Streams.1.h"
#include "winrt/impl/Windows.Devices.PointOfService.Provider.1.h"

WINRT_EXPORT namespace winrt::Windows::Devices::PointOfService::Provider {

}

namespace winrt::impl {

}

WINRT_EXPORT namespace winrt::Windows::Devices::PointOfService::Provider {

struct WINRT_EBO BarcodeScannerDisableScannerRequest :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest,
    impl::require<BarcodeScannerDisableScannerRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2>
{
    BarcodeScannerDisableScannerRequest(std::nullptr_t) noexcept {}
    using impl::consume_t<BarcodeScannerDisableScannerRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2>::ReportFailedAsync;
    using Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest::ReportFailedAsync;
};

struct WINRT_EBO BarcodeScannerDisableScannerRequestEventArgs :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs
{
    BarcodeScannerDisableScannerRequestEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerEnableScannerRequest :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest,
    impl::require<BarcodeScannerEnableScannerRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2>
{
    BarcodeScannerEnableScannerRequest(std::nullptr_t) noexcept {}
    using impl::consume_t<BarcodeScannerEnableScannerRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2>::ReportFailedAsync;
    using Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest::ReportFailedAsync;
};

struct WINRT_EBO BarcodeScannerEnableScannerRequestEventArgs :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs
{
    BarcodeScannerEnableScannerRequestEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerFrameReader :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader,
    impl::require<BarcodeScannerFrameReader, Windows::Foundation::IClosable>
{
    BarcodeScannerFrameReader(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerFrameReaderFrameArrivedEventArgs :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReaderFrameArrivedEventArgs
{
    BarcodeScannerFrameReaderFrameArrivedEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerGetSymbologyAttributesRequest :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest,
    impl::require<BarcodeScannerGetSymbologyAttributesRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2>
{
    BarcodeScannerGetSymbologyAttributesRequest(std::nullptr_t) noexcept {}
    using impl::consume_t<BarcodeScannerGetSymbologyAttributesRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2>::ReportFailedAsync;
    using Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest::ReportFailedAsync;
};

struct WINRT_EBO BarcodeScannerGetSymbologyAttributesRequestEventArgs :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs
{
    BarcodeScannerGetSymbologyAttributesRequestEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerHideVideoPreviewRequest :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest,
    impl::require<BarcodeScannerHideVideoPreviewRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2>
{
    BarcodeScannerHideVideoPreviewRequest(std::nullptr_t) noexcept {}
    using impl::consume_t<BarcodeScannerHideVideoPreviewRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2>::ReportFailedAsync;
    using Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest::ReportFailedAsync;
};

struct WINRT_EBO BarcodeScannerHideVideoPreviewRequestEventArgs :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs
{
    BarcodeScannerHideVideoPreviewRequestEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerProviderConnection :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection,
    impl::require<BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2, Windows::Foundation::IClosable>
{
    BarcodeScannerProviderConnection(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerProviderTriggerDetails :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderTriggerDetails
{
    BarcodeScannerProviderTriggerDetails(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerSetActiveSymbologiesRequest :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest,
    impl::require<BarcodeScannerSetActiveSymbologiesRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2>
{
    BarcodeScannerSetActiveSymbologiesRequest(std::nullptr_t) noexcept {}
    using impl::consume_t<BarcodeScannerSetActiveSymbologiesRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2>::ReportFailedAsync;
    using Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest::ReportFailedAsync;
};

struct WINRT_EBO BarcodeScannerSetActiveSymbologiesRequestEventArgs :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs
{
    BarcodeScannerSetActiveSymbologiesRequestEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerSetSymbologyAttributesRequest :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest,
    impl::require<BarcodeScannerSetSymbologyAttributesRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2>
{
    BarcodeScannerSetSymbologyAttributesRequest(std::nullptr_t) noexcept {}
    using impl::consume_t<BarcodeScannerSetSymbologyAttributesRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2>::ReportFailedAsync;
    using Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest::ReportFailedAsync;
};

struct WINRT_EBO BarcodeScannerSetSymbologyAttributesRequestEventArgs :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs
{
    BarcodeScannerSetSymbologyAttributesRequestEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerStartSoftwareTriggerRequest :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest,
    impl::require<BarcodeScannerStartSoftwareTriggerRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2>
{
    BarcodeScannerStartSoftwareTriggerRequest(std::nullptr_t) noexcept {}
    using impl::consume_t<BarcodeScannerStartSoftwareTriggerRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2>::ReportFailedAsync;
    using Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest::ReportFailedAsync;
};

struct WINRT_EBO BarcodeScannerStartSoftwareTriggerRequestEventArgs :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs
{
    BarcodeScannerStartSoftwareTriggerRequestEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerStopSoftwareTriggerRequest :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest,
    impl::require<BarcodeScannerStopSoftwareTriggerRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2>
{
    BarcodeScannerStopSoftwareTriggerRequest(std::nullptr_t) noexcept {}
    using impl::consume_t<BarcodeScannerStopSoftwareTriggerRequest, Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2>::ReportFailedAsync;
    using Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest::ReportFailedAsync;
};

struct WINRT_EBO BarcodeScannerStopSoftwareTriggerRequestEventArgs :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs
{
    BarcodeScannerStopSoftwareTriggerRequestEventArgs(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeScannerVideoFrame :
    Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame,
    impl::require<BarcodeScannerVideoFrame, Windows::Foundation::IClosable>
{
    BarcodeScannerVideoFrame(std::nullptr_t) noexcept {}
};

struct WINRT_EBO BarcodeSymbologyAttributesBuilder :
    Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder
{
    BarcodeSymbologyAttributesBuilder(std::nullptr_t) noexcept {}
    BarcodeSymbologyAttributesBuilder();
};

}
