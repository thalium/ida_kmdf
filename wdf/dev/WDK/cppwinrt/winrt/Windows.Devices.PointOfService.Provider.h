// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.PointOfService.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Devices.PointOfService.Provider.2.h"
#include "winrt/Windows.Devices.PointOfService.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequest2<D>::ReportFailedAsync(int32_t reason) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2)->ReportFailedWithFailedReasonAsync(reason, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, get_abi(failedReasonDescription), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequest consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequestEventArgs<D>::Request() const
{
    Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerDisableScannerRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequest2<D>::ReportFailedAsync(int32_t reason) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2)->ReportFailedWithFailedReasonAsync(reason, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, get_abi(failedReasonDescription), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequest consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequestEventArgs<D>::Request() const
{
    Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerEnableScannerRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::StartAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->StartAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::StopAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->StopAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerVideoFrame> consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::TryAcquireLatestFrameAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerVideoFrame> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->TryAcquireLatestFrameAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::Connection() const
{
    Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::FrameArrived(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader, Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReaderFrameArrivedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->add_FrameArrived(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::FrameArrived_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::FrameArrived(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader, Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReaderFrameArrivedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, FrameArrived_revoker>(this, FrameArrived(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReader<D>::FrameArrived(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader)->remove_FrameArrived(get_abi(token)));
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerFrameReaderFrameArrivedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReaderFrameArrivedEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequest<D>::Symbology() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest)->get_Symbology(&value));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequest<D>::ReportCompletedAsync(Windows::Devices::PointOfService::BarcodeSymbologyAttributes const& attributes) const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest)->ReportCompletedAsync(get_abi(attributes), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequest2<D>::ReportFailedAsync(int32_t reason) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2)->ReportFailedWithFailedReasonAsync(reason, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, get_abi(failedReasonDescription), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequest consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequestEventArgs<D>::Request() const
{
    Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerGetSymbologyAttributesRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequest2<D>::ReportFailedAsync(int32_t reason) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2)->ReportFailedWithFailedReasonAsync(reason, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, get_abi(failedReasonDescription), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequest consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequestEventArgs<D>::Request() const
{
    Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerHideVideoPreviewRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_Id(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::VideoDeviceId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_VideoDeviceId(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<uint32_t> consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SupportedSymbologies() const
{
    Windows::Foundation::Collections::IVector<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_SupportedSymbologies(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::CompanyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_CompanyName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::CompanyName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->put_CompanyName(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->put_Name(get_abi(value)));
}

template <typename D> hstring consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Version() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->get_Version(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Version(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->put_Version(get_abi(value)));
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::Start() const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->Start());
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::ReportScannedDataAsync(Windows::Devices::PointOfService::BarcodeScannerReport const& report) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->ReportScannedDataAsync(get_abi(report), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::ReportTriggerStateAsync(Windows::Devices::PointOfService::Provider::BarcodeScannerTriggerState const& state) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->ReportTriggerStateAsync(get_abi(state), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::ReportErrorAsync(Windows::Devices::PointOfService::UnifiedPosErrorData const& errorData) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->ReportErrorAsync(get_abi(errorData), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::ReportErrorAsync(Windows::Devices::PointOfService::UnifiedPosErrorData const& errorData, bool isRetriable, Windows::Devices::PointOfService::BarcodeScannerReport const& scanReport) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->ReportErrorAsyncWithScanReport(get_abi(errorData), isRetriable, get_abi(scanReport), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::EnableScannerRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_EnableScannerRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::EnableScannerRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::EnableScannerRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, EnableScannerRequested_revoker>(this, EnableScannerRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::EnableScannerRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_EnableScannerRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::DisableScannerRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_DisableScannerRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::DisableScannerRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::DisableScannerRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, DisableScannerRequested_revoker>(this, DisableScannerRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::DisableScannerRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_DisableScannerRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetActiveSymbologiesRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_SetActiveSymbologiesRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetActiveSymbologiesRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetActiveSymbologiesRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SetActiveSymbologiesRequested_revoker>(this, SetActiveSymbologiesRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetActiveSymbologiesRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_SetActiveSymbologiesRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StartSoftwareTriggerRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_StartSoftwareTriggerRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StartSoftwareTriggerRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StartSoftwareTriggerRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StartSoftwareTriggerRequested_revoker>(this, StartSoftwareTriggerRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StartSoftwareTriggerRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_StartSoftwareTriggerRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StopSoftwareTriggerRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_StopSoftwareTriggerRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StopSoftwareTriggerRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StopSoftwareTriggerRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StopSoftwareTriggerRequested_revoker>(this, StopSoftwareTriggerRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::StopSoftwareTriggerRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_StopSoftwareTriggerRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::GetBarcodeSymbologyAttributesRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_GetBarcodeSymbologyAttributesRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::GetBarcodeSymbologyAttributesRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::GetBarcodeSymbologyAttributesRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, GetBarcodeSymbologyAttributesRequested_revoker>(this, GetBarcodeSymbologyAttributesRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::GetBarcodeSymbologyAttributesRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_GetBarcodeSymbologyAttributesRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetBarcodeSymbologyAttributesRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_SetBarcodeSymbologyAttributesRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetBarcodeSymbologyAttributesRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetBarcodeSymbologyAttributesRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, SetBarcodeSymbologyAttributesRequested_revoker>(this, SetBarcodeSymbologyAttributesRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::SetBarcodeSymbologyAttributesRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_SetBarcodeSymbologyAttributesRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::HideVideoPreviewRequested(Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequestEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->add_HideVideoPreviewRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::HideVideoPreviewRequested_revoker consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::HideVideoPreviewRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequestEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, HideVideoPreviewRequested_revoker>(this, HideVideoPreviewRequested(handler));
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection<D>::HideVideoPreviewRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection)->remove_HideVideoPreviewRequested(get_abi(token)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader> consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection2<D>::CreateFrameReaderAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2)->CreateFrameReaderAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader> consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection2<D>::CreateFrameReaderAsync(Windows::Graphics::Imaging::BitmapPixelFormat const& preferredFormat) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2)->CreateFrameReaderWithFormatAsync(get_abi(preferredFormat), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader> consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderConnection2<D>::CreateFrameReaderAsync(Windows::Graphics::Imaging::BitmapPixelFormat const& preferredFormat, Windows::Graphics::Imaging::BitmapSize const& preferredSize) const
{
    Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2)->CreateFrameReaderWithFormatAndSizeAsync(get_abi(preferredFormat), get_abi(preferredSize), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerProviderTriggerDetails<D>::Connection() const
{
    Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderTriggerDetails)->get_Connection(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequest<D>::Symbologies() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest)->get_Symbologies(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequest2<D>::ReportFailedAsync(int32_t reason) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2)->ReportFailedWithFailedReasonAsync(reason, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, get_abi(failedReasonDescription), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequest consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequestEventArgs<D>::Request() const
{
    Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetActiveSymbologiesRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest<D>::Symbology() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest)->get_Symbology(&value));
    return value;
}

template <typename D> Windows::Devices::PointOfService::BarcodeSymbologyAttributes consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest<D>::Attributes() const
{
    Windows::Devices::PointOfService::BarcodeSymbologyAttributes value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest)->get_Attributes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest2<D>::ReportFailedAsync(int32_t reason) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2)->ReportFailedWithFailedReasonAsync(reason, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, get_abi(failedReasonDescription), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequest consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequestEventArgs<D>::Request() const
{
    Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerSetSymbologyAttributesRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequest2<D>::ReportFailedAsync(int32_t reason) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2)->ReportFailedWithFailedReasonAsync(reason, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, get_abi(failedReasonDescription), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequest consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequestEventArgs<D>::Request() const
{
    Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStartSoftwareTriggerRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequest<D>::ReportCompletedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest)->ReportCompletedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequest<D>::ReportFailedAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest)->ReportFailedAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequest2<D>::ReportFailedAsync(int32_t reason) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2)->ReportFailedWithFailedReasonAsync(reason, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequest2<D>::ReportFailedAsync(int32_t reason, param::hstring const& failedReasonDescription) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2)->ReportFailedWithFailedReasonAndDescriptionAsync(reason, get_abi(failedReasonDescription), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequest consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequestEventArgs<D>::Request() const
{
    Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerStopSoftwareTriggerRequestEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Imaging::BitmapPixelFormat consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerVideoFrame<D>::Format() const
{
    Windows::Graphics::Imaging::BitmapPixelFormat value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame)->get_Format(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerVideoFrame<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame)->get_Width(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerVideoFrame<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame)->get_Height(&value));
    return value;
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Devices_PointOfService_Provider_IBarcodeScannerVideoFrame<D>::PixelData() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame)->get_PixelData(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsCheckDigitValidationSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->get_IsCheckDigitValidationSupported(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsCheckDigitValidationSupported(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->put_IsCheckDigitValidationSupported(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsCheckDigitTransmissionSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->get_IsCheckDigitTransmissionSupported(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsCheckDigitTransmissionSupported(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->put_IsCheckDigitTransmissionSupported(value));
}

template <typename D> bool consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsDecodeLengthSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->get_IsDecodeLengthSupported(&value));
    return value;
}

template <typename D> void consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::IsDecodeLengthSupported(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->put_IsDecodeLengthSupported(value));
}

template <typename D> Windows::Devices::PointOfService::BarcodeSymbologyAttributes consume_Windows_Devices_PointOfService_Provider_IBarcodeSymbologyAttributesBuilder<D>::CreateAttributes() const
{
    Windows::Devices::PointOfService::BarcodeSymbologyAttributes value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder)->CreateAttributes(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest>
{
    int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2>
{
    int32_t WINRT_CALL ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequest));
            *value = detach_from<Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequest>(this->shim().Request());
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
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest>
{
    int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2>
{
    int32_t WINRT_CALL ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequest));
            *value = detach_from<Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequest>(this->shim().Request());
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
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader>
{
    int32_t WINRT_CALL StartAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryAcquireLatestFrameAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryAcquireLatestFrameAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerVideoFrame>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerVideoFrame>>(this->shim().TryAcquireLatestFrameAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection));
            *value = detach_from<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_FrameArrived(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameArrived, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader, Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReaderFrameArrivedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().FrameArrived(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader, Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReaderFrameArrivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FrameArrived(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FrameArrived, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReaderFrameArrivedEventArgs> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReaderFrameArrivedEventArgs>
{
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
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest>
{
    int32_t WINRT_CALL get_Symbology(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Symbology, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Symbology());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void* attributes, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Devices::PointOfService::BarcodeSymbologyAttributes const);
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync(*reinterpret_cast<Windows::Devices::PointOfService::BarcodeSymbologyAttributes const*>(&attributes)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2>
{
    int32_t WINRT_CALL ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequest));
            *value = detach_from<Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequest>(this->shim().Request());
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
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest>
{
    int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2>
{
    int32_t WINRT_CALL ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequest));
            *value = detach_from<Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequest>(this->shim().Request());
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
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection>
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

    int32_t WINRT_CALL get_VideoDeviceId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VideoDeviceId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VideoDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SupportedSymbologies(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportedSymbologies, WINRT_WRAP(Windows::Foundation::Collections::IVector<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVector<uint32_t>>(this->shim().SupportedSymbologies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompanyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompanyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CompanyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CompanyName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompanyName, WINRT_WRAP(void), hstring const&);
            this->shim().CompanyName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

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

    int32_t WINRT_CALL put_Name(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Name, WINRT_WRAP(void), hstring const&);
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Version(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Version, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Version());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Version(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Version, WINRT_WRAP(void), hstring const&);
            this->shim().Version(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL ReportScannedDataAsync(void* report, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportScannedDataAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Devices::PointOfService::BarcodeScannerReport const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportScannedDataAsync(*reinterpret_cast<Windows::Devices::PointOfService::BarcodeScannerReport const*>(&report)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportTriggerStateAsync(Windows::Devices::PointOfService::Provider::BarcodeScannerTriggerState state, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportTriggerStateAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Devices::PointOfService::Provider::BarcodeScannerTriggerState const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportTriggerStateAsync(*reinterpret_cast<Windows::Devices::PointOfService::Provider::BarcodeScannerTriggerState const*>(&state)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportErrorAsync(void* errorData, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportErrorAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Devices::PointOfService::UnifiedPosErrorData const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportErrorAsync(*reinterpret_cast<Windows::Devices::PointOfService::UnifiedPosErrorData const*>(&errorData)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportErrorAsyncWithScanReport(void* errorData, bool isRetriable, void* scanReport, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportErrorAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Devices::PointOfService::UnifiedPosErrorData const, bool, Windows::Devices::PointOfService::BarcodeScannerReport const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportErrorAsync(*reinterpret_cast<Windows::Devices::PointOfService::UnifiedPosErrorData const*>(&errorData), isRetriable, *reinterpret_cast<Windows::Devices::PointOfService::BarcodeScannerReport const*>(&scanReport)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_EnableScannerRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EnableScannerRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().EnableScannerRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_EnableScannerRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(EnableScannerRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().EnableScannerRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_DisableScannerRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisableScannerRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().DisableScannerRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_DisableScannerRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(DisableScannerRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().DisableScannerRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SetActiveSymbologiesRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetActiveSymbologiesRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SetActiveSymbologiesRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SetActiveSymbologiesRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SetActiveSymbologiesRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SetActiveSymbologiesRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_StartSoftwareTriggerRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartSoftwareTriggerRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StartSoftwareTriggerRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StartSoftwareTriggerRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StartSoftwareTriggerRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StartSoftwareTriggerRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_StopSoftwareTriggerRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopSoftwareTriggerRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().StopSoftwareTriggerRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StopSoftwareTriggerRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StopSoftwareTriggerRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StopSoftwareTriggerRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_GetBarcodeSymbologyAttributesRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetBarcodeSymbologyAttributesRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().GetBarcodeSymbologyAttributesRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_GetBarcodeSymbologyAttributesRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(GetBarcodeSymbologyAttributesRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().GetBarcodeSymbologyAttributesRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_SetBarcodeSymbologyAttributesRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBarcodeSymbologyAttributesRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().SetBarcodeSymbologyAttributesRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SetBarcodeSymbologyAttributesRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SetBarcodeSymbologyAttributesRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SetBarcodeSymbologyAttributesRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_HideVideoPreviewRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HideVideoPreviewRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequestEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().HideVideoPreviewRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection, Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequestEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HideVideoPreviewRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HideVideoPreviewRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HideVideoPreviewRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2>
{
    int32_t WINRT_CALL CreateFrameReaderAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFrameReaderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>>(this->shim().CreateFrameReaderAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFrameReaderWithFormatAsync(Windows::Graphics::Imaging::BitmapPixelFormat preferredFormat, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFrameReaderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>), Windows::Graphics::Imaging::BitmapPixelFormat const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>>(this->shim().CreateFrameReaderAsync(*reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&preferredFormat)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFrameReaderWithFormatAndSizeAsync(Windows::Graphics::Imaging::BitmapPixelFormat preferredFormat, struct struct_Windows_Graphics_Imaging_BitmapSize preferredSize, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFrameReaderAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>), Windows::Graphics::Imaging::BitmapPixelFormat const, Windows::Graphics::Imaging::BitmapSize const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader>>(this->shim().CreateFrameReaderAsync(*reinterpret_cast<Windows::Graphics::Imaging::BitmapPixelFormat const*>(&preferredFormat), *reinterpret_cast<Windows::Graphics::Imaging::BitmapSize const*>(&preferredSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderTriggerDetails> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderTriggerDetails>
{
    int32_t WINRT_CALL get_Connection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Connection, WINRT_WRAP(Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection));
            *value = detach_from<Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection>(this->shim().Connection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest>
{
    int32_t WINRT_CALL get_Symbologies(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Symbologies, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().Symbologies());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2>
{
    int32_t WINRT_CALL ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequest));
            *value = detach_from<Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequest>(this->shim().Request());
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
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest>
{
    int32_t WINRT_CALL get_Symbology(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Symbology, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Symbology());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Attributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Attributes, WINRT_WRAP(Windows::Devices::PointOfService::BarcodeSymbologyAttributes));
            *value = detach_from<Windows::Devices::PointOfService::BarcodeSymbologyAttributes>(this->shim().Attributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2>
{
    int32_t WINRT_CALL ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequest));
            *value = detach_from<Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequest>(this->shim().Request());
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
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest>
{
    int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2>
{
    int32_t WINRT_CALL ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequest));
            *value = detach_from<Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequest>(this->shim().Request());
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
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest>
{
    int32_t WINRT_CALL ReportCompletedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCompletedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2>
{
    int32_t WINRT_CALL ReportFailedWithFailedReasonAsync(int32_t reason, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportFailedWithFailedReasonAndDescriptionAsync(int32_t reason, void* failedReasonDescription, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportFailedAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), int32_t, hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().ReportFailedAsync(reason, *reinterpret_cast<hstring const*>(&failedReasonDescription)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequest));
            *value = detach_from<Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequest>(this->shim().Request());
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
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame>
{
    int32_t WINRT_CALL get_Format(Windows::Graphics::Imaging::BitmapPixelFormat* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Format, WINRT_WRAP(Windows::Graphics::Imaging::BitmapPixelFormat));
            *value = detach_from<Windows::Graphics::Imaging::BitmapPixelFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Width(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Width, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Height(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Height, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PixelData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelData, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().PixelData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder> : produce_base<D, Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder>
{
    int32_t WINRT_CALL get_IsCheckDigitValidationSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCheckDigitValidationSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCheckDigitValidationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCheckDigitValidationSupported(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCheckDigitValidationSupported, WINRT_WRAP(void), bool);
            this->shim().IsCheckDigitValidationSupported(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCheckDigitTransmissionSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCheckDigitTransmissionSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCheckDigitTransmissionSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsCheckDigitTransmissionSupported(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCheckDigitTransmissionSupported, WINRT_WRAP(void), bool);
            this->shim().IsCheckDigitTransmissionSupported(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsDecodeLengthSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDecodeLengthSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsDecodeLengthSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsDecodeLengthSupported(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsDecodeLengthSupported, WINRT_WRAP(void), bool);
            this->shim().IsDecodeLengthSupported(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateAttributes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAttributes, WINRT_WRAP(Windows::Devices::PointOfService::BarcodeSymbologyAttributes));
            *value = detach_from<Windows::Devices::PointOfService::BarcodeSymbologyAttributes>(this->shim().CreateAttributes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Devices::PointOfService::Provider {

inline BarcodeSymbologyAttributesBuilder::BarcodeSymbologyAttributesBuilder() :
    BarcodeSymbologyAttributesBuilder(impl::call_factory<BarcodeSymbologyAttributesBuilder>([](auto&& f) { return f.template ActivateInstance<BarcodeSymbologyAttributesBuilder>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequest2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerDisableScannerRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequest2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerEnableScannerRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReader> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReaderFrameArrivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerFrameReaderFrameArrivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequest2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerGetSymbologyAttributesRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequest2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerHideVideoPreviewRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderConnection2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequest2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetActiveSymbologiesRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequest2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerSetSymbologyAttributesRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequest2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStartSoftwareTriggerRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequest2> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerStopSoftwareTriggerRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeScannerVideoFrame> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::IBarcodeSymbologyAttributesBuilder> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerDisableScannerRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerEnableScannerRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReader> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReaderFrameArrivedEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerFrameReaderFrameArrivedEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerGetSymbologyAttributesRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerHideVideoPreviewRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderConnection> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderTriggerDetails> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerProviderTriggerDetails> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetActiveSymbologiesRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerSetSymbologyAttributesRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStartSoftwareTriggerRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequest> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequest> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequestEventArgs> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerStopSoftwareTriggerRequestEventArgs> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerVideoFrame> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeScannerVideoFrame> {};
template<> struct hash<winrt::Windows::Devices::PointOfService::Provider::BarcodeSymbologyAttributesBuilder> : winrt::impl::hash_base<winrt::Windows::Devices::PointOfService::Provider::BarcodeSymbologyAttributesBuilder> {};

}
