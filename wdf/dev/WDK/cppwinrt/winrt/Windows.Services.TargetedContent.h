// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Services.TargetedContent.2.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Services_TargetedContent_ITargetedContentAction<D>::InvokeAsync() const
{
    Windows::Foundation::IAsyncAction asyncAction{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentAction)->InvokeAsync(put_abi(asyncAction)));
    return asyncAction;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Services_TargetedContent_ITargetedContentAvailabilityChangedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentAvailabilityChangedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Services_TargetedContent_ITargetedContentChangedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentChangedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_TargetedContent_ITargetedContentChangedEventArgs<D>::HasPreviousContentExpired() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentChangedEventArgs)->get_HasPreviousContentExpired(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_TargetedContent_ITargetedContentCollection<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentCollection)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_TargetedContent_ITargetedContentCollection<D>::ReportInteraction(Windows::Services::TargetedContent::TargetedContentInteraction const& interaction) const
{
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentCollection)->ReportInteraction(get_abi(interaction)));
}

template <typename D> void consume_Windows_Services_TargetedContent_ITargetedContentCollection<D>::ReportCustomInteraction(param::hstring const& customInteractionName) const
{
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentCollection)->ReportCustomInteraction(get_abi(customInteractionName)));
}

template <typename D> hstring consume_Windows_Services_TargetedContent_ITargetedContentCollection<D>::Path() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentCollection)->get_Path(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Services::TargetedContent::TargetedContentValue> consume_Windows_Services_TargetedContent_ITargetedContentCollection<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Services::TargetedContent::TargetedContentValue> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentCollection)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentCollection> consume_Windows_Services_TargetedContent_ITargetedContentCollection<D>::Collections() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentCollection> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentCollection)->get_Collections(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentItem> consume_Windows_Services_TargetedContent_ITargetedContentCollection<D>::Items() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentCollection)->get_Items(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_TargetedContent_ITargetedContentContainer<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentContainer)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_Services_TargetedContent_ITargetedContentContainer<D>::Timestamp() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentContainer)->get_Timestamp(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentAvailability consume_Windows_Services_TargetedContent_ITargetedContentContainer<D>::Availability() const
{
    Windows::Services::TargetedContent::TargetedContentAvailability value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentContainer)->get_Availability(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentCollection consume_Windows_Services_TargetedContent_ITargetedContentContainer<D>::Content() const
{
    Windows::Services::TargetedContent::TargetedContentCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentContainer)->get_Content(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentObject consume_Windows_Services_TargetedContent_ITargetedContentContainer<D>::SelectSingleObject(param::hstring const& path) const
{
    Windows::Services::TargetedContent::TargetedContentObject value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentContainer)->SelectSingleObject(get_abi(path), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentContainer> consume_Windows_Services_TargetedContent_ITargetedContentContainerStatics<D>::GetAsync(param::hstring const& contentId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentContainer> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentContainerStatics)->GetAsync(get_abi(contentId), put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> uint32_t consume_Windows_Services_TargetedContent_ITargetedContentImage<D>::Height() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentImage)->get_Height(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_Services_TargetedContent_ITargetedContentImage<D>::Width() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentImage)->get_Width(&value));
    return value;
}

template <typename D> hstring consume_Windows_Services_TargetedContent_ITargetedContentItem<D>::Path() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentItem)->get_Path(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_TargetedContent_ITargetedContentItem<D>::ReportInteraction(Windows::Services::TargetedContent::TargetedContentInteraction const& interaction) const
{
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentItem)->ReportInteraction(get_abi(interaction)));
}

template <typename D> void consume_Windows_Services_TargetedContent_ITargetedContentItem<D>::ReportCustomInteraction(param::hstring const& customInteractionName) const
{
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentItem)->ReportCustomInteraction(get_abi(customInteractionName)));
}

template <typename D> Windows::Services::TargetedContent::TargetedContentItemState consume_Windows_Services_TargetedContent_ITargetedContentItem<D>::State() const
{
    Windows::Services::TargetedContent::TargetedContentItemState value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentItem)->get_State(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Services::TargetedContent::TargetedContentValue> consume_Windows_Services_TargetedContent_ITargetedContentItem<D>::Properties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Services::TargetedContent::TargetedContentValue> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentItem)->get_Properties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentCollection> consume_Windows_Services_TargetedContent_ITargetedContentItem<D>::Collections() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentCollection> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentItem)->get_Collections(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_TargetedContent_ITargetedContentItemState<D>::ShouldDisplay() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentItemState)->get_ShouldDisplay(&value));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentAppInstallationState consume_Windows_Services_TargetedContent_ITargetedContentItemState<D>::AppInstallationState() const
{
    Windows::Services::TargetedContent::TargetedContentAppInstallationState value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentItemState)->get_AppInstallationState(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentObjectKind consume_Windows_Services_TargetedContent_ITargetedContentObject<D>::ObjectKind() const
{
    Windows::Services::TargetedContent::TargetedContentObjectKind value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentObject)->get_ObjectKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentCollection consume_Windows_Services_TargetedContent_ITargetedContentObject<D>::Collection() const
{
    Windows::Services::TargetedContent::TargetedContentCollection value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentObject)->get_Collection(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentItem consume_Windows_Services_TargetedContent_ITargetedContentObject<D>::Item() const
{
    Windows::Services::TargetedContent::TargetedContentItem value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentObject)->get_Item(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentValue consume_Windows_Services_TargetedContent_ITargetedContentObject<D>::Value() const
{
    Windows::Services::TargetedContent::TargetedContentValue value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentObject)->get_Value(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Deferral consume_Windows_Services_TargetedContent_ITargetedContentStateChangedEventArgs<D>::GetDeferral() const
{
    Windows::Foundation::Deferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentStateChangedEventArgs)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscription)->get_Id(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentContainer> consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::GetContentContainerAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentContainer> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscription)->GetContentContainerAsync(put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> winrt::event_token consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::ContentChanged(Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentChangedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscription)->add_ContentChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::ContentChanged_revoker consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::ContentChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ContentChanged_revoker>(this, ContentChanged(handler));
}

template <typename D> void consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::ContentChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscription)->remove_ContentChanged(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::AvailabilityChanged(Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentAvailabilityChangedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscription)->add_AvailabilityChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::AvailabilityChanged_revoker consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::AvailabilityChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentAvailabilityChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, AvailabilityChanged_revoker>(this, AvailabilityChanged(handler));
}

template <typename D> void consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::AvailabilityChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscription)->remove_AvailabilityChanged(get_abi(cookie)));
}

template <typename D> winrt::event_token consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::StateChanged(Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentStateChangedEventArgs> const& handler) const
{
    winrt::event_token cookie{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscription)->add_StateChanged(get_abi(handler), put_abi(cookie)));
    return cookie;
}

template <typename D> typename consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::StateChanged_revoker consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::StateChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentStateChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
}

template <typename D> void consume_Windows_Services_TargetedContent_ITargetedContentSubscription<D>::StateChanged(winrt::event_token const& cookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscription)->remove_StateChanged(get_abi(cookie)));
}

template <typename D> hstring consume_Windows_Services_TargetedContent_ITargetedContentSubscriptionOptions<D>::SubscriptionId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscriptionOptions)->get_SubscriptionId(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_Services_TargetedContent_ITargetedContentSubscriptionOptions<D>::AllowPartialContentAvailability() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscriptionOptions)->get_AllowPartialContentAvailability(&value));
    return value;
}

template <typename D> void consume_Windows_Services_TargetedContent_ITargetedContentSubscriptionOptions<D>::AllowPartialContentAvailability(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscriptionOptions)->put_AllowPartialContentAvailability(value));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Services_TargetedContent_ITargetedContentSubscriptionOptions<D>::CloudQueryParameters() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscriptionOptions)->get_CloudQueryParameters(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Services_TargetedContent_ITargetedContentSubscriptionOptions<D>::LocalFilters() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscriptionOptions)->get_LocalFilters(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Services_TargetedContent_ITargetedContentSubscriptionOptions<D>::Update() const
{
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscriptionOptions)->Update());
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentSubscription> consume_Windows_Services_TargetedContent_ITargetedContentSubscriptionStatics<D>::GetAsync(param::hstring const& subscriptionId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentSubscription> asyncOperation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscriptionStatics)->GetAsync(get_abi(subscriptionId), put_abi(asyncOperation)));
    return asyncOperation;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentSubscriptionOptions consume_Windows_Services_TargetedContent_ITargetedContentSubscriptionStatics<D>::GetOptions(param::hstring const& subscriptionId) const
{
    Windows::Services::TargetedContent::TargetedContentSubscriptionOptions value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentSubscriptionStatics)->GetOptions(get_abi(subscriptionId), put_abi(value)));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentValueKind consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::ValueKind() const
{
    Windows::Services::TargetedContent::TargetedContentValueKind value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_ValueKind(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::Path() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_Path(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::String() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_String(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> double consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::Number() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_Number(&value));
    return value;
}

template <typename D> bool consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::Boolean() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_Boolean(&value));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentFile consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::File() const
{
    Windows::Services::TargetedContent::TargetedContentFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_File(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentImage consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::ImageFile() const
{
    Windows::Services::TargetedContent::TargetedContentImage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_ImageFile(put_abi(value)));
    return value;
}

template <typename D> Windows::Services::TargetedContent::TargetedContentAction consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::Action() const
{
    Windows::Services::TargetedContent::TargetedContentAction value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_Action(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::Strings() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_Strings(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Foundation::Uri> consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::Uris() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Foundation::Uri> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_Uris(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<double> consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::Numbers() const
{
    Windows::Foundation::Collections::IVectorView<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_Numbers(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<bool> consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::Booleans() const
{
    Windows::Foundation::Collections::IVectorView<bool> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_Booleans(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentFile> consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::Files() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentFile> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_Files(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentImage> consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::ImageFiles() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentImage> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_ImageFiles(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentAction> consume_Windows_Services_TargetedContent_ITargetedContentValue<D>::Actions() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentAction> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Services::TargetedContent::ITargetedContentValue)->get_Actions(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentAction> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentAction>
{
    int32_t WINRT_CALL InvokeAsync(void** asyncAction) noexcept final
    {
        try
        {
            *asyncAction = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InvokeAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *asyncAction = detach_from<Windows::Foundation::IAsyncAction>(this->shim().InvokeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentAvailabilityChangedEventArgs> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentAvailabilityChangedEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentChangedEventArgs> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentChangedEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasPreviousContentExpired(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasPreviousContentExpired, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasPreviousContentExpired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentCollection> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentCollection>
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

    int32_t WINRT_CALL ReportInteraction(Windows::Services::TargetedContent::TargetedContentInteraction interaction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportInteraction, WINRT_WRAP(void), Windows::Services::TargetedContent::TargetedContentInteraction const&);
            this->shim().ReportInteraction(*reinterpret_cast<Windows::Services::TargetedContent::TargetedContentInteraction const*>(&interaction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCustomInteraction(void* customInteractionName) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCustomInteraction, WINRT_WRAP(void), hstring const&);
            this->shim().ReportCustomInteraction(*reinterpret_cast<hstring const*>(&customInteractionName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Path());
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Services::TargetedContent::TargetedContentValue>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Services::TargetedContent::TargetedContentValue>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Collections(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Collections, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentCollection>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentCollection>>(this->shim().Collections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Items(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Items, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentItem>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentItem>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentContainer> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentContainer>
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

    int32_t WINRT_CALL get_Timestamp(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Timestamp, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Availability(Windows::Services::TargetedContent::TargetedContentAvailability* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Availability, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentAvailability));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentAvailability>(this->shim().Availability());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Content(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Content, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentCollection));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentCollection>(this->shim().Content());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SelectSingleObject(void* path, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectSingleObject, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentObject), hstring const&);
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentObject>(this->shim().SelectSingleObject(*reinterpret_cast<hstring const*>(&path)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentContainerStatics> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentContainerStatics>
{
    int32_t WINRT_CALL GetAsync(void* contentId, void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentContainer>), hstring const);
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentContainer>>(this->shim().GetAsync(*reinterpret_cast<hstring const*>(&contentId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentImage> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentImage>
{
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
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentItem> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentItem>
{
    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportInteraction(Windows::Services::TargetedContent::TargetedContentInteraction interaction) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportInteraction, WINRT_WRAP(void), Windows::Services::TargetedContent::TargetedContentInteraction const&);
            this->shim().ReportInteraction(*reinterpret_cast<Windows::Services::TargetedContent::TargetedContentInteraction const*>(&interaction));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReportCustomInteraction(void* customInteractionName) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReportCustomInteraction, WINRT_WRAP(void), hstring const&);
            this->shim().ReportCustomInteraction(*reinterpret_cast<hstring const*>(&customInteractionName));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_State(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(State, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentItemState));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentItemState>(this->shim().State());
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
            WINRT_ASSERT_DECLARATION(Properties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Services::TargetedContent::TargetedContentValue>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Services::TargetedContent::TargetedContentValue>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Collections(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Collections, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentCollection>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentCollection>>(this->shim().Collections());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentItemState> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentItemState>
{
    int32_t WINRT_CALL get_ShouldDisplay(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShouldDisplay, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShouldDisplay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AppInstallationState(Windows::Services::TargetedContent::TargetedContentAppInstallationState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AppInstallationState, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentAppInstallationState));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentAppInstallationState>(this->shim().AppInstallationState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentObject> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentObject>
{
    int32_t WINRT_CALL get_ObjectKind(Windows::Services::TargetedContent::TargetedContentObjectKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ObjectKind, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentObjectKind));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentObjectKind>(this->shim().ObjectKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Collection(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Collection, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentCollection));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentCollection>(this->shim().Collection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Item(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Item, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentItem));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentItem>(this->shim().Item());
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
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentValue));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentValue>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentStateChangedEventArgs> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentStateChangedEventArgs>
{
    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Foundation::Deferral));
            *value = detach_from<Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentSubscription> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentSubscription>
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

    int32_t WINRT_CALL GetContentContainerAsync(void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContentContainerAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentContainer>));
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentContainer>>(this->shim().GetContentContainerAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_ContentChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentChangedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().ContentChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ContentChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ContentChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ContentChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_AvailabilityChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AvailabilityChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentAvailabilityChangedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().AvailabilityChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentAvailabilityChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_AvailabilityChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(AvailabilityChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().AvailabilityChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }

    int32_t WINRT_CALL add_StateChanged(void* handler, winrt::event_token* cookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentStateChangedEventArgs> const&);
            *cookie = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Services::TargetedContent::TargetedContentSubscription, Windows::Services::TargetedContent::TargetedContentStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_StateChanged(winrt::event_token cookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(StateChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentSubscriptionOptions> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentSubscriptionOptions>
{
    int32_t WINRT_CALL get_SubscriptionId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SubscriptionId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().SubscriptionId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowPartialContentAvailability(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowPartialContentAvailability, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowPartialContentAvailability());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowPartialContentAvailability(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowPartialContentAvailability, WINRT_WRAP(void), bool);
            this->shim().AllowPartialContentAvailability(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CloudQueryParameters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CloudQueryParameters, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().CloudQueryParameters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocalFilters(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalFilters, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().LocalFilters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Update() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Update, WINRT_WRAP(void));
            this->shim().Update();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentSubscriptionStatics> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentSubscriptionStatics>
{
    int32_t WINRT_CALL GetAsync(void* subscriptionId, void** asyncOperation) noexcept final
    {
        try
        {
            *asyncOperation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentSubscription>), hstring const);
            *asyncOperation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentSubscription>>(this->shim().GetAsync(*reinterpret_cast<hstring const*>(&subscriptionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetOptions(void* subscriptionId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOptions, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentSubscriptionOptions), hstring const&);
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentSubscriptionOptions>(this->shim().GetOptions(*reinterpret_cast<hstring const*>(&subscriptionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Services::TargetedContent::ITargetedContentValue> : produce_base<D, Windows::Services::TargetedContent::ITargetedContentValue>
{
    int32_t WINRT_CALL get_ValueKind(Windows::Services::TargetedContent::TargetedContentValueKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ValueKind, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentValueKind));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentValueKind>(this->shim().ValueKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_String(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(String, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().String());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Number(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Number, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Number());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Boolean(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Boolean, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Boolean());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_File(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(File, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentFile));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImageFile(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageFile, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentImage));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentImage>(this->shim().ImageFile());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Action(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Action, WINRT_WRAP(Windows::Services::TargetedContent::TargetedContentAction));
            *value = detach_from<Windows::Services::TargetedContent::TargetedContentAction>(this->shim().Action());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Strings(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Strings, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Strings());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Uris(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uris, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Foundation::Uri>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Uri>>(this->shim().Uris());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Numbers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Numbers, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<double>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<double>>(this->shim().Numbers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Booleans(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Booleans, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<bool>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<bool>>(this->shim().Booleans());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Files(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Files, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentFile>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentFile>>(this->shim().Files());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ImageFiles(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ImageFiles, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentImage>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentImage>>(this->shim().ImageFiles());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Actions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Actions, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentAction>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::TargetedContent::TargetedContentAction>>(this->shim().Actions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Services::TargetedContent {

inline Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentContainer> TargetedContentContainer::GetAsync(param::hstring const& contentId)
{
    return impl::call_factory<TargetedContentContainer, Windows::Services::TargetedContent::ITargetedContentContainerStatics>([&](auto&& f) { return f.GetAsync(contentId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Services::TargetedContent::TargetedContentSubscription> TargetedContentSubscription::GetAsync(param::hstring const& subscriptionId)
{
    return impl::call_factory<TargetedContentSubscription, Windows::Services::TargetedContent::ITargetedContentSubscriptionStatics>([&](auto&& f) { return f.GetAsync(subscriptionId); });
}

inline Windows::Services::TargetedContent::TargetedContentSubscriptionOptions TargetedContentSubscription::GetOptions(param::hstring const& subscriptionId)
{
    return impl::call_factory<TargetedContentSubscription, Windows::Services::TargetedContent::ITargetedContentSubscriptionStatics>([&](auto&& f) { return f.GetOptions(subscriptionId); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentAction> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentAction> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentAvailabilityChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentAvailabilityChangedEventArgs> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentChangedEventArgs> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentCollection> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentCollection> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentContainer> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentContainer> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentContainerStatics> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentContainerStatics> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentImage> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentImage> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentItem> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentItem> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentItemState> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentItemState> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentObject> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentObject> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentSubscription> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentSubscription> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentSubscriptionOptions> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentSubscriptionOptions> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentSubscriptionStatics> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentSubscriptionStatics> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::ITargetedContentValue> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::ITargetedContentValue> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentAction> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentAction> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentAvailabilityChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentAvailabilityChangedEventArgs> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentChangedEventArgs> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentCollection> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentCollection> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentContainer> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentContainer> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentFile> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentFile> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentImage> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentImage> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentItem> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentItem> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentItemState> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentItemState> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentObject> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentObject> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentStateChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentStateChangedEventArgs> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentSubscription> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentSubscription> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentSubscriptionOptions> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentSubscriptionOptions> {};
template<> struct hash<winrt::Windows::Services::TargetedContent::TargetedContentValue> : winrt::impl::hash_base<winrt::Windows::Services::TargetedContent::TargetedContentValue> {};

}
