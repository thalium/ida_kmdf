// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Devices.Geolocation.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Services.Maps.2.h"
#include "winrt/impl/Windows.Services.Maps.LocalSearch.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.2.h"
#include "winrt/impl/Windows.UI.Xaml.Controls.Maps.2.h"
#include "winrt/Windows.UI.Xaml.Controls.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_ICustomMapTileDataSource<D>::BitmapRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSource)->add_BitmapRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_ICustomMapTileDataSource<D>::BitmapRequested_revoker consume_Windows_UI_Xaml_Controls_Maps_ICustomMapTileDataSource<D>::BitmapRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, BitmapRequested_revoker>(this, BitmapRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_ICustomMapTileDataSource<D>::BitmapRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSource)->remove_BitmapRequested(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource consume_Windows_UI_Xaml_Controls_Maps_ICustomMapTileDataSourceFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSourceFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IHttpMapTileDataSource<D>::UriFormatString() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource)->get_UriFormatString(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IHttpMapTileDataSource<D>::UriFormatString(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource)->put_UriFormatString(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_UI_Xaml_Controls_Maps_IHttpMapTileDataSource<D>::AdditionalRequestHeaders() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource)->get_AdditionalRequestHeaders(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IHttpMapTileDataSource<D>::AllowCaching() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource)->get_AllowCaching(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IHttpMapTileDataSource<D>::AllowCaching(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource)->put_AllowCaching(value));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IHttpMapTileDataSource<D>::UriRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileUriRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource)->add_UriRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IHttpMapTileDataSource<D>::UriRequested_revoker consume_Windows_UI_Xaml_Controls_Maps_IHttpMapTileDataSource<D>::UriRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileUriRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, UriRequested_revoker>(this, UriRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IHttpMapTileDataSource<D>::UriRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource)->remove_UriRequested(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource consume_Windows_UI_Xaml_Controls_Maps_IHttpMapTileDataSourceFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSourceFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource consume_Windows_UI_Xaml_Controls_Maps_IHttpMapTileDataSourceFactory<D>::CreateInstanceWithUriFormatString(param::hstring const& uriFormatString, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSourceFactory)->CreateInstanceWithUriFormatString(get_abi(uriFormatString), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_ILocalMapTileDataSource<D>::UriFormatString() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSource)->get_UriFormatString(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_ILocalMapTileDataSource<D>::UriFormatString(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSource)->put_UriFormatString(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_ILocalMapTileDataSource<D>::UriRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileUriRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSource)->add_UriRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_ILocalMapTileDataSource<D>::UriRequested_revoker consume_Windows_UI_Xaml_Controls_Maps_ILocalMapTileDataSource<D>::UriRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileUriRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, UriRequested_revoker>(this, UriRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_ILocalMapTileDataSource<D>::UriRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSource)->remove_UriRequested(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource consume_Windows_UI_Xaml_Controls_Maps_ILocalMapTileDataSourceFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSourceFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource consume_Windows_UI_Xaml_Controls_Maps_ILocalMapTileDataSourceFactory<D>::CreateInstanceWithUriFormatString(param::hstring const& uriFormatString, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSourceFactory)->CreateInstanceWithUriFormatString(get_abi(uriFormatString), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCamera consume_Windows_UI_Xaml_Controls_Maps_IMapActualCameraChangedEventArgs<D>::Camera() const
{
    Windows::UI::Xaml::Controls::Maps::MapCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangedEventArgs)->get_Camera(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason consume_Windows_UI_Xaml_Controls_Maps_IMapActualCameraChangedEventArgs2<D>::ChangeReason() const
{
    Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangedEventArgs2)->get_ChangeReason(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCamera consume_Windows_UI_Xaml_Controls_Maps_IMapActualCameraChangingEventArgs<D>::Camera() const
{
    Windows::UI::Xaml::Controls::Maps::MapCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangingEventArgs)->get_Camera(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason consume_Windows_UI_Xaml_Controls_Maps_IMapActualCameraChangingEventArgs2<D>::ChangeReason() const
{
    Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangingEventArgs2)->get_ChangeReason(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapBillboard<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboard)->get_Location(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapBillboard<D>::Location(Windows::Devices::Geolocation::Geopoint const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboard)->put_Location(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapBillboard<D>::NormalizedAnchorPoint() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboard)->get_NormalizedAnchorPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapBillboard<D>::NormalizedAnchorPoint(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboard)->put_NormalizedAnchorPoint(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_UI_Xaml_Controls_Maps_IMapBillboard<D>::Image() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboard)->get_Image(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapBillboard<D>::Image(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboard)->put_Image(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior consume_Windows_UI_Xaml_Controls_Maps_IMapBillboard<D>::CollisionBehaviorDesired() const
{
    Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboard)->get_CollisionBehaviorDesired(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapBillboard<D>::CollisionBehaviorDesired(Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboard)->put_CollisionBehaviorDesired(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCamera consume_Windows_UI_Xaml_Controls_Maps_IMapBillboard<D>::ReferenceCamera() const
{
    Windows::UI::Xaml::Controls::Maps::MapCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboard)->get_ReferenceCamera(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapBillboard consume_Windows_UI_Xaml_Controls_Maps_IMapBillboardFactory<D>::CreateInstanceFromCamera(Windows::UI::Xaml::Controls::Maps::MapCamera const& camera) const
{
    Windows::UI::Xaml::Controls::Maps::MapBillboard value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboardFactory)->CreateInstanceFromCamera(get_abi(camera), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapBillboardStatics<D>::LocationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboardStatics)->get_LocationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapBillboardStatics<D>::NormalizedAnchorPointProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboardStatics)->get_NormalizedAnchorPointProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapBillboardStatics<D>::CollisionBehaviorDesiredProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapBillboardStatics)->get_CollisionBehaviorDesiredProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapCamera<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCamera)->get_Location(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapCamera<D>::Location(Windows::Devices::Geolocation::Geopoint const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCamera)->put_Location(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapCamera<D>::Heading() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCamera)->get_Heading(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapCamera<D>::Heading(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCamera)->put_Heading(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapCamera<D>::Pitch() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCamera)->get_Pitch(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapCamera<D>::Pitch(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCamera)->put_Pitch(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapCamera<D>::Roll() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCamera)->get_Roll(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapCamera<D>::Roll(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCamera)->put_Roll(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapCamera<D>::FieldOfView() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCamera)->get_FieldOfView(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapCamera<D>::FieldOfView(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCamera)->put_FieldOfView(value));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCamera consume_Windows_UI_Xaml_Controls_Maps_IMapCameraFactory<D>::CreateInstanceWithLocation(Windows::Devices::Geolocation::Geopoint const& location) const
{
    Windows::UI::Xaml::Controls::Maps::MapCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCameraFactory)->CreateInstanceWithLocation(get_abi(location), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCamera consume_Windows_UI_Xaml_Controls_Maps_IMapCameraFactory<D>::CreateInstanceWithLocationAndHeading(Windows::Devices::Geolocation::Geopoint const& location, double headingInDegrees) const
{
    Windows::UI::Xaml::Controls::Maps::MapCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCameraFactory)->CreateInstanceWithLocationAndHeading(get_abi(location), headingInDegrees, put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCamera consume_Windows_UI_Xaml_Controls_Maps_IMapCameraFactory<D>::CreateInstanceWithLocationHeadingAndPitch(Windows::Devices::Geolocation::Geopoint const& location, double headingInDegrees, double pitchInDegrees) const
{
    Windows::UI::Xaml::Controls::Maps::MapCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCameraFactory)->CreateInstanceWithLocationHeadingAndPitch(get_abi(location), headingInDegrees, pitchInDegrees, put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCamera consume_Windows_UI_Xaml_Controls_Maps_IMapCameraFactory<D>::CreateInstanceWithLocationHeadingPitchRollAndFieldOfView(Windows::Devices::Geolocation::Geopoint const& location, double headingInDegrees, double pitchInDegrees, double rollInDegrees, double fieldOfViewInDegrees) const
{
    Windows::UI::Xaml::Controls::Maps::MapCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCameraFactory)->CreateInstanceWithLocationHeadingPitchRollAndFieldOfView(get_abi(location), headingInDegrees, pitchInDegrees, rollInDegrees, fieldOfViewInDegrees, put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapContextRequestedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapContextRequestedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapContextRequestedEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapContextRequestedEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement> consume_Windows_UI_Xaml_Controls_Maps_IMapContextRequestedEventArgs<D>::MapElements() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapContextRequestedEventArgs)->get_MapElements(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::Center() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_Center(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::Center(Windows::Devices::Geolocation::Geopoint const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_Center(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::Children() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_Children(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapColorScheme consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::ColorScheme() const
{
    Windows::UI::Xaml::Controls::Maps::MapColorScheme value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_ColorScheme(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::ColorScheme(Windows::UI::Xaml::Controls::Maps::MapColorScheme const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_ColorScheme(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::DesiredPitch() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_DesiredPitch(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::DesiredPitch(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_DesiredPitch(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::Heading() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_Heading(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::Heading(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_Heading(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::LandmarksVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_LandmarksVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::LandmarksVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_LandmarksVisible(value));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapLoadingStatus consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::LoadingStatus() const
{
    Windows::UI::Xaml::Controls::Maps::MapLoadingStatus value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_LoadingStatus(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapServiceToken() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_MapServiceToken(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapServiceToken(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_MapServiceToken(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MaxZoomLevel() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_MaxZoomLevel(&value));
    return value;
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MinZoomLevel() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_MinZoomLevel(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::PedestrianFeaturesVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_PedestrianFeaturesVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::PedestrianFeaturesVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_PedestrianFeaturesVisible(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::Pitch() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_Pitch(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapStyle consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::Style() const
{
    Windows::UI::Xaml::Controls::Maps::MapStyle value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_Style(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::Style(Windows::UI::Xaml::Controls::Maps::MapStyle const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_Style(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TrafficFlowVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_TrafficFlowVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TrafficFlowVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_TrafficFlowVisible(value));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TransformOrigin() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_TransformOrigin(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TransformOrigin(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_TransformOrigin(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapWatermarkMode consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::WatermarkMode() const
{
    Windows::UI::Xaml::Controls::Maps::MapWatermarkMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_WatermarkMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::WatermarkMode(Windows::UI::Xaml::Controls::Maps::MapWatermarkMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_WatermarkMode(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::ZoomLevel() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_ZoomLevel(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::ZoomLevel(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->put_ZoomLevel(value));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement> consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapElements() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_MapElements(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapRouteView> consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::Routes() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapRouteView> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_Routes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapTileSource> consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TileSources() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapTileSource> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->get_TileSources(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::CenterChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->add_CenterChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::CenterChanged_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::CenterChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, CenterChanged_revoker>(this, CenterChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::CenterChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->remove_CenterChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::HeadingChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->add_HeadingChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::HeadingChanged_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::HeadingChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, HeadingChanged_revoker>(this, HeadingChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::HeadingChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->remove_HeadingChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::LoadingStatusChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->add_LoadingStatusChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::LoadingStatusChanged_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::LoadingStatusChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, LoadingStatusChanged_revoker>(this, LoadingStatusChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::LoadingStatusChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->remove_LoadingStatusChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapDoubleTapped(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->add_MapDoubleTapped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapDoubleTapped_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapDoubleTapped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapDoubleTapped_revoker>(this, MapDoubleTapped(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapDoubleTapped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->remove_MapDoubleTapped(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapHolding(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->add_MapHolding(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapHolding_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapHolding(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapHolding_revoker>(this, MapHolding(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapHolding(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->remove_MapHolding(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapTapped(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->add_MapTapped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapTapped_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapTapped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapTapped_revoker>(this, MapTapped(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::MapTapped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->remove_MapTapped(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::PitchChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->add_PitchChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::PitchChanged_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::PitchChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, PitchChanged_revoker>(this, PitchChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::PitchChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->remove_PitchChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TransformOriginChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->add_TransformOriginChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TransformOriginChanged_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TransformOriginChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, TransformOriginChanged_revoker>(this, TransformOriginChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TransformOriginChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->remove_TransformOriginChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::ZoomLevelChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->add_ZoomLevelChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::ZoomLevelChanged_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::ZoomLevelChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, ZoomLevelChanged_revoker>(this, ZoomLevelChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::ZoomLevelChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->remove_ZoomLevelChanged(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement> consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::FindMapElementsAtOffset(Windows::Foundation::Point const& offset) const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->FindMapElementsAtOffset(get_abi(offset), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::GetLocationFromOffset(Windows::Foundation::Point const& offset, Windows::Devices::Geolocation::Geopoint& location) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->GetLocationFromOffset(get_abi(offset), put_abi(location)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::GetOffsetFromLocation(Windows::Devices::Geolocation::Geopoint const& location, Windows::Foundation::Point& offset) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->GetOffsetFromLocation(get_abi(location), put_abi(offset)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::IsLocationInView(Windows::Devices::Geolocation::Geopoint const& location, bool& isInView) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->IsLocationInView(get_abi(location), &isInView));
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TrySetViewBoundsAsync(Windows::Devices::Geolocation::GeoboundingBox const& bounds, optional<Windows::UI::Xaml::Thickness> const& margin, Windows::UI::Xaml::Controls::Maps::MapAnimationKind const& animation) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->TrySetViewBoundsAsync(get_abi(bounds), get_abi(margin), get_abi(animation), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TrySetViewAsync(Windows::Devices::Geolocation::Geopoint const& center) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->TrySetViewWithCenterAsync(get_abi(center), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TrySetViewAsync(Windows::Devices::Geolocation::Geopoint const& center, optional<double> const& zoomLevel) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->TrySetViewWithCenterAndZoomAsync(get_abi(center), get_abi(zoomLevel), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TrySetViewAsync(Windows::Devices::Geolocation::Geopoint const& center, optional<double> const& zoomLevel, optional<double> const& heading, optional<double> const& desiredPitch) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->TrySetViewWithCenterZoomHeadingAndPitchAsync(get_abi(center), get_abi(zoomLevel), get_abi(heading), get_abi(desiredPitch), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl<D>::TrySetViewAsync(Windows::Devices::Geolocation::Geopoint const& center, optional<double> const& zoomLevel, optional<double> const& heading, optional<double> const& desiredPitch, Windows::UI::Xaml::Controls::Maps::MapAnimationKind const& animation) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl)->TrySetViewWithCenterZoomHeadingPitchAndAnimationAsync(get_abi(center), get_abi(zoomLevel), get_abi(heading), get_abi(desiredPitch), get_abi(animation), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::BusinessLandmarksVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_BusinessLandmarksVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::BusinessLandmarksVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->put_BusinessLandmarksVisible(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TransitFeaturesVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_TransitFeaturesVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TransitFeaturesVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->put_TransitFeaturesVisible(value));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapPanInteractionMode consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::PanInteractionMode() const
{
    Windows::UI::Xaml::Controls::Maps::MapPanInteractionMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_PanInteractionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::PanInteractionMode(Windows::UI::Xaml::Controls::Maps::MapPanInteractionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->put_PanInteractionMode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapInteractionMode consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::RotateInteractionMode() const
{
    Windows::UI::Xaml::Controls::Maps::MapInteractionMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_RotateInteractionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::RotateInteractionMode(Windows::UI::Xaml::Controls::Maps::MapInteractionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->put_RotateInteractionMode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapInteractionMode consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TiltInteractionMode() const
{
    Windows::UI::Xaml::Controls::Maps::MapInteractionMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_TiltInteractionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TiltInteractionMode(Windows::UI::Xaml::Controls::Maps::MapInteractionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->put_TiltInteractionMode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapInteractionMode consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::ZoomInteractionMode() const
{
    Windows::UI::Xaml::Controls::Maps::MapInteractionMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_ZoomInteractionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::ZoomInteractionMode(Windows::UI::Xaml::Controls::Maps::MapInteractionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->put_ZoomInteractionMode(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::Is3DSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_Is3DSupported(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::IsStreetsideSupported() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_IsStreetsideSupported(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapScene consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::Scene() const
{
    Windows::UI::Xaml::Controls::Maps::MapScene value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_Scene(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::Scene(Windows::UI::Xaml::Controls::Maps::MapScene const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->put_Scene(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCamera consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::ActualCamera() const
{
    Windows::UI::Xaml::Controls::Maps::MapCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_ActualCamera(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCamera consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TargetCamera() const
{
    Windows::UI::Xaml::Controls::Maps::MapCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_TargetCamera(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCustomExperience consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::CustomExperience() const
{
    Windows::UI::Xaml::Controls::Maps::MapCustomExperience value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->get_CustomExperience(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::CustomExperience(Windows::UI::Xaml::Controls::Maps::MapCustomExperience const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->put_CustomExperience(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementClick(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementClickEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->add_MapElementClick(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementClick_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementClick(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementClickEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapElementClick_revoker>(this, MapElementClick(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementClick(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->remove_MapElementClick(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementPointerEntered(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementPointerEnteredEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->add_MapElementPointerEntered(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementPointerEntered_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementPointerEntered(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementPointerEnteredEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapElementPointerEntered_revoker>(this, MapElementPointerEntered(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementPointerEntered(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->remove_MapElementPointerEntered(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementPointerExited(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementPointerExitedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->add_MapElementPointerExited(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementPointerExited_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementPointerExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementPointerExitedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapElementPointerExited_revoker>(this, MapElementPointerExited(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::MapElementPointerExited(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->remove_MapElementPointerExited(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::ActualCameraChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapActualCameraChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->add_ActualCameraChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::ActualCameraChanged_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::ActualCameraChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapActualCameraChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ActualCameraChanged_revoker>(this, ActualCameraChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::ActualCameraChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->remove_ActualCameraChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::ActualCameraChanging(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapActualCameraChangingEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->add_ActualCameraChanging(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::ActualCameraChanging_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::ActualCameraChanging(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapActualCameraChangingEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, ActualCameraChanging_revoker>(this, ActualCameraChanging(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::ActualCameraChanging(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->remove_ActualCameraChanging(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TargetCameraChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapTargetCameraChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->add_TargetCameraChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TargetCameraChanged_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TargetCameraChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapTargetCameraChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, TargetCameraChanged_revoker>(this, TargetCameraChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TargetCameraChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->remove_TargetCameraChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::CustomExperienceChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapCustomExperienceChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->add_CustomExperienceChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::CustomExperienceChanged_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::CustomExperienceChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapCustomExperienceChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, CustomExperienceChanged_revoker>(this, CustomExperienceChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::CustomExperienceChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->remove_CustomExperienceChanged(get_abi(token)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::StartContinuousRotate(double rateInDegreesPerSecond) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->StartContinuousRotate(rateInDegreesPerSecond));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::StopContinuousRotate() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->StopContinuousRotate());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::StartContinuousTilt(double rateInDegreesPerSecond) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->StartContinuousTilt(rateInDegreesPerSecond));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::StopContinuousTilt() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->StopContinuousTilt());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::StartContinuousZoom(double rateOfChangePerSecond) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->StartContinuousZoom(rateOfChangePerSecond));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::StopContinuousZoom() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->StopContinuousZoom());
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TryRotateAsync(double degrees) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->TryRotateAsync(degrees, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TryRotateToAsync(double angleInDegrees) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->TryRotateToAsync(angleInDegrees, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TryTiltAsync(double degrees) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->TryTiltAsync(degrees, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TryTiltToAsync(double angleInDegrees) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->TryTiltToAsync(angleInDegrees, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TryZoomInAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->TryZoomInAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TryZoomOutAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->TryZoomOutAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TryZoomToAsync(double zoomLevel) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->TryZoomToAsync(zoomLevel, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TrySetSceneAsync(Windows::UI::Xaml::Controls::Maps::MapScene const& scene) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->TrySetSceneAsync(get_abi(scene), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl2<D>::TrySetSceneAsync(Windows::UI::Xaml::Controls::Maps::MapScene const& scene, Windows::UI::Xaml::Controls::Maps::MapAnimationKind const& animationKind) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl2)->TrySetSceneWithAnimationAsync(get_abi(scene), get_abi(animationKind), put_abi(operation)));
    return operation;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl3<D>::MapRightTapped(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapRightTappedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl3)->add_MapRightTapped(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl3<D>::MapRightTapped_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl3<D>::MapRightTapped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapRightTappedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapRightTapped_revoker>(this, MapRightTapped(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl3<D>::MapRightTapped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl3)->remove_MapRightTapped(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl4<D>::BusinessLandmarksEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl4)->get_BusinessLandmarksEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl4<D>::BusinessLandmarksEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl4)->put_BusinessLandmarksEnabled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl4<D>::TransitFeaturesEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl4)->get_TransitFeaturesEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl4<D>::TransitFeaturesEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl4)->put_TransitFeaturesEnabled(value));
}

template <typename D> Windows::Devices::Geolocation::Geopath consume_Windows_UI_Xaml_Controls_Maps_IMapControl4<D>::GetVisibleRegion(Windows::UI::Xaml::Controls::Maps::MapVisibleRegionKind const& region) const
{
    Windows::Devices::Geolocation::Geopath result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl4)->GetVisibleRegion(get_abi(region), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapProjection consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::MapProjection() const
{
    Windows::UI::Xaml::Controls::Maps::MapProjection value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->get_MapProjection(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::MapProjection(Windows::UI::Xaml::Controls::Maps::MapProjection const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->put_MapProjection(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapStyleSheet consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::StyleSheet() const
{
    Windows::UI::Xaml::Controls::Maps::MapStyleSheet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->get_StyleSheet(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::StyleSheet(Windows::UI::Xaml::Controls::Maps::MapStyleSheet const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->put_StyleSheet(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Thickness consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::ViewPadding() const
{
    Windows::UI::Xaml::Thickness value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->get_ViewPadding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::ViewPadding(Windows::UI::Xaml::Thickness const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->put_ViewPadding(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::MapContextRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapContextRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->add_MapContextRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::MapContextRequested_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::MapContextRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapContextRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapContextRequested_revoker>(this, MapContextRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::MapContextRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->remove_MapContextRequested(get_abi(token)));
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement> consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::FindMapElementsAtOffset(Windows::Foundation::Point const& offset, double radius) const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->FindMapElementsAtOffsetWithRadius(get_abi(offset), radius, put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::GetLocationFromOffset(Windows::Foundation::Point const& offset, Windows::Devices::Geolocation::AltitudeReferenceSystem const& desiredReferenceSystem, Windows::Devices::Geolocation::Geopoint& location) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->GetLocationFromOffsetWithReferenceSystem(get_abi(offset), get_abi(desiredReferenceSystem), put_abi(location)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::StartContinuousPan(double horizontalPixelsPerSecond, double verticalPixelsPerSecond) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->StartContinuousPan(horizontalPixelsPerSecond, verticalPixelsPerSecond));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::StopContinuousPan() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->StopContinuousPan());
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::TryPanAsync(double horizontalPixels, double verticalPixels) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->TryPanAsync(horizontalPixels, verticalPixels, put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_Xaml_Controls_Maps_IMapControl5<D>::TryPanToAsync(Windows::Devices::Geolocation::Geopoint const& location) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl5)->TryPanToAsync(get_abi(location), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapLayer> consume_Windows_UI_Xaml_Controls_Maps_IMapControl6<D>::Layers() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapLayer> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl6)->get_Layers(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl6<D>::Layers(param::vector<Windows::UI::Xaml::Controls::Maps::MapLayer> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl6)->put_Layers(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl6<D>::TryGetLocationFromOffset(Windows::Foundation::Point const& offset, Windows::Devices::Geolocation::Geopoint& location) const
{
    bool returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl6)->TryGetLocationFromOffset(get_abi(offset), put_abi(location), &returnValue));
    return returnValue;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl6<D>::TryGetLocationFromOffset(Windows::Foundation::Point const& offset, Windows::Devices::Geolocation::AltitudeReferenceSystem const& desiredReferenceSystem, Windows::Devices::Geolocation::Geopoint& location) const
{
    bool returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl6)->TryGetLocationFromOffsetWithReferenceSystem(get_abi(offset), get_abi(desiredReferenceSystem), put_abi(location), &returnValue));
    return returnValue;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapControl7<D>::Region() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl7)->get_Region(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControl7<D>::Region(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl7)->put_Region(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl8<D>::CanTiltDown() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl8)->get_CanTiltDown(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl8<D>::CanTiltUp() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl8)->get_CanTiltUp(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl8<D>::CanZoomIn() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl8)->get_CanZoomIn(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapControl8<D>::CanZoomOut() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControl8)->get_CanZoomOut(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation> consume_Windows_UI_Xaml_Controls_Maps_IMapControlBusinessLandmarkClickEventArgs<D>::LocalLocations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkClickEventArgs)->get_LocalLocations(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation> consume_Windows_UI_Xaml_Controls_Maps_IMapControlBusinessLandmarkPointerEnteredEventArgs<D>::LocalLocations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkPointerEnteredEventArgs)->get_LocalLocations(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation> consume_Windows_UI_Xaml_Controls_Maps_IMapControlBusinessLandmarkPointerExitedEventArgs<D>::LocalLocations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkPointerExitedEventArgs)->get_LocalLocations(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation> consume_Windows_UI_Xaml_Controls_Maps_IMapControlBusinessLandmarkRightTappedEventArgs<D>::LocalLocations() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkRightTappedEventArgs)->get_LocalLocations(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::BusinessLandmarkClick(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkClickEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper)->add_BusinessLandmarkClick(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::BusinessLandmarkClick_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::BusinessLandmarkClick(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkClickEventArgs> const& value) const
{
    return impl::make_event_revoker<D, BusinessLandmarkClick_revoker>(this, BusinessLandmarkClick(value));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::BusinessLandmarkClick(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper)->remove_BusinessLandmarkClick(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::TransitFeatureClick(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureClickEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper)->add_TransitFeatureClick(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::TransitFeatureClick_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::TransitFeatureClick(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureClickEventArgs> const& value) const
{
    return impl::make_event_revoker<D, TransitFeatureClick_revoker>(this, TransitFeatureClick(value));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::TransitFeatureClick(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper)->remove_TransitFeatureClick(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::BusinessLandmarkRightTapped(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkRightTappedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper)->add_BusinessLandmarkRightTapped(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::BusinessLandmarkRightTapped_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::BusinessLandmarkRightTapped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkRightTappedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, BusinessLandmarkRightTapped_revoker>(this, BusinessLandmarkRightTapped(value));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::BusinessLandmarkRightTapped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper)->remove_BusinessLandmarkRightTapped(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::TransitFeatureRightTapped(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureRightTappedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper)->add_TransitFeatureRightTapped(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::TransitFeatureRightTapped_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::TransitFeatureRightTapped(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureRightTappedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, TransitFeatureRightTapped_revoker>(this, TransitFeatureRightTapped(value));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper<D>::TransitFeatureRightTapped(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper)->remove_TransitFeatureRightTapped(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::BusinessLandmarkPointerEntered(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerEnteredEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2)->add_BusinessLandmarkPointerEntered(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::BusinessLandmarkPointerEntered_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::BusinessLandmarkPointerEntered(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerEnteredEventArgs> const& value) const
{
    return impl::make_event_revoker<D, BusinessLandmarkPointerEntered_revoker>(this, BusinessLandmarkPointerEntered(value));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::BusinessLandmarkPointerEntered(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2)->remove_BusinessLandmarkPointerEntered(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::TransitFeaturePointerEntered(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerEnteredEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2)->add_TransitFeaturePointerEntered(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::TransitFeaturePointerEntered_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::TransitFeaturePointerEntered(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerEnteredEventArgs> const& value) const
{
    return impl::make_event_revoker<D, TransitFeaturePointerEntered_revoker>(this, TransitFeaturePointerEntered(value));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::TransitFeaturePointerEntered(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2)->remove_TransitFeaturePointerEntered(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::BusinessLandmarkPointerExited(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerExitedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2)->add_BusinessLandmarkPointerExited(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::BusinessLandmarkPointerExited_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::BusinessLandmarkPointerExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerExitedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, BusinessLandmarkPointerExited_revoker>(this, BusinessLandmarkPointerExited(value));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::BusinessLandmarkPointerExited(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2)->remove_BusinessLandmarkPointerExited(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::TransitFeaturePointerExited(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerExitedEventArgs> const& value) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2)->add_TransitFeaturePointerExited(get_abi(value), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::TransitFeaturePointerExited_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::TransitFeaturePointerExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerExitedEventArgs> const& value) const
{
    return impl::make_event_revoker<D, TransitFeaturePointerExited_revoker>(this, TransitFeaturePointerExited(value));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelper2<D>::TransitFeaturePointerExited(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2)->remove_TransitFeaturePointerExited(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapControlDataHelper consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelperFactory<D>::CreateInstance(Windows::UI::Xaml::Controls::Maps::MapControl const& map) const
{
    Windows::UI::Xaml::Controls::Maps::MapControlDataHelper instance{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperFactory)->CreateInstance(get_abi(map), put_abi(instance)));
    return instance;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapControl consume_Windows_UI_Xaml_Controls_Maps_IMapControlDataHelperStatics<D>::CreateMapControl(bool rasterRenderMode) const
{
    Windows::UI::Xaml::Controls::Maps::MapControl returnValue{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperStatics)->CreateMapControl(rasterRenderMode, put_abi(returnValue)));
    return returnValue;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::CenterProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_CenterProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::ChildrenProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_ChildrenProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::ColorSchemeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_ColorSchemeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::DesiredPitchProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_DesiredPitchProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::HeadingProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_HeadingProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::LandmarksVisibleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_LandmarksVisibleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::LoadingStatusProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_LoadingStatusProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::MapServiceTokenProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_MapServiceTokenProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::PedestrianFeaturesVisibleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_PedestrianFeaturesVisibleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::PitchProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_PitchProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::StyleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_StyleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::TrafficFlowVisibleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_TrafficFlowVisibleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::TransformOriginProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_TransformOriginProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::WatermarkModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_WatermarkModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::ZoomLevelProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_ZoomLevelProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::MapElementsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_MapElementsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::RoutesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_RoutesProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::TileSourcesProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_TileSourcesProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::LocationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_LocationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::GetLocation(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::Devices::Geolocation::Geopoint result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->GetLocation(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::SetLocation(Windows::UI::Xaml::DependencyObject const& element, Windows::Devices::Geolocation::Geopoint const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->SetLocation(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::NormalizedAnchorPointProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->get_NormalizedAnchorPointProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::GetNormalizedAnchorPoint(Windows::UI::Xaml::DependencyObject const& element) const
{
    Windows::Foundation::Point result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->GetNormalizedAnchorPoint(get_abi(element), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics<D>::SetNormalizedAnchorPoint(Windows::UI::Xaml::DependencyObject const& element, Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics)->SetNormalizedAnchorPoint(get_abi(element), get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics2<D>::BusinessLandmarksVisibleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics2)->get_BusinessLandmarksVisibleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics2<D>::TransitFeaturesVisibleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics2)->get_TransitFeaturesVisibleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics2<D>::PanInteractionModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics2)->get_PanInteractionModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics2<D>::RotateInteractionModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics2)->get_RotateInteractionModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics2<D>::TiltInteractionModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics2)->get_TiltInteractionModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics2<D>::ZoomInteractionModeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics2)->get_ZoomInteractionModeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics2<D>::Is3DSupportedProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics2)->get_Is3DSupportedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics2<D>::IsStreetsideSupportedProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics2)->get_IsStreetsideSupportedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics2<D>::SceneProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics2)->get_SceneProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics4<D>::BusinessLandmarksEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics4)->get_BusinessLandmarksEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics4<D>::TransitFeaturesEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics4)->get_TransitFeaturesEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics5<D>::MapProjectionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics5)->get_MapProjectionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics5<D>::StyleSheetProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics5)->get_StyleSheetProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics5<D>::ViewPaddingProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics5)->get_ViewPaddingProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics6<D>::LayersProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics6)->get_LayersProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics7<D>::RegionProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics7)->get_RegionProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics8<D>::CanTiltDownProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics8)->get_CanTiltDownProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics8<D>::CanTiltUpProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics8)->get_CanTiltUpProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics8<D>::CanZoomInProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics8)->get_CanZoomInProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapControlStatics8<D>::CanZoomOutProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlStatics8)->get_CanZoomOutProperty(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeatureClickEventArgs<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureClickEventArgs)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeatureClickEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureClickEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeatureClickEventArgs<D>::TransitProperties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureClickEventArgs)->get_TransitProperties(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeaturePointerEnteredEventArgs<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerEnteredEventArgs)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeaturePointerEnteredEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerEnteredEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeaturePointerEnteredEventArgs<D>::TransitProperties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerEnteredEventArgs)->get_TransitProperties(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeaturePointerExitedEventArgs<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerExitedEventArgs)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeaturePointerExitedEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerExitedEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeaturePointerExitedEventArgs<D>::TransitProperties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerExitedEventArgs)->get_TransitProperties(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeatureRightTappedEventArgs<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureRightTappedEventArgs)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeatureRightTappedEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureRightTappedEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> consume_Windows_UI_Xaml_Controls_Maps_IMapControlTransitFeatureRightTappedEventArgs<D>::TransitProperties() const
{
    Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureRightTappedEventArgs)->get_TransitProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCustomExperience consume_Windows_UI_Xaml_Controls_Maps_IMapCustomExperienceFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::MapCustomExperience value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapCustomExperienceFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapElement<D>::ZIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement)->get_ZIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement<D>::ZIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement)->put_ZIndex(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapElement<D>::Visible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement)->get_Visible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement<D>::Visible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement)->put_Visible(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapElement2<D>::MapTabIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement2)->get_MapTabIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement2<D>::MapTabIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement2)->put_MapTabIndex(value));
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapElement3<D>::MapStyleSheetEntry() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3)->get_MapStyleSheetEntry(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement3<D>::MapStyleSheetEntry(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3)->put_MapStyleSheetEntry(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapElement3<D>::MapStyleSheetEntryState() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3)->get_MapStyleSheetEntryState(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement3<D>::MapStyleSheetEntryState(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3)->put_MapStyleSheetEntryState(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Controls_Maps_IMapElement3<D>::Tag() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3)->get_Tag(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement3<D>::Tag(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3)->put_Tag(get_abi(value)));
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->get_Location(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Location(Windows::Devices::Geolocation::Geopoint const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->put_Location(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapModel3D consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Model() const
{
    Windows::UI::Xaml::Controls::Maps::MapModel3D value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->get_Model(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Model(Windows::UI::Xaml::Controls::Maps::MapModel3D const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->put_Model(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Heading() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->get_Heading(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Heading(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->put_Heading(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Pitch() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->get_Pitch(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Pitch(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->put_Pitch(value));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Roll() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->get_Roll(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Roll(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->put_Roll(value));
}

template <typename D> Windows::Foundation::Numerics::float3 consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Scale() const
{
    Windows::Foundation::Numerics::float3 value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->get_Scale(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement3D<D>::Scale(Windows::Foundation::Numerics::float3 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3D)->put_Scale(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElement3DStatics<D>::LocationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics)->get_LocationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElement3DStatics<D>::HeadingProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics)->get_HeadingProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElement3DStatics<D>::PitchProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics)->get_PitchProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElement3DStatics<D>::RollProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics)->get_RollProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElement3DStatics<D>::ScaleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics)->get_ScaleProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapElement4<D>::IsEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement4)->get_IsEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElement4<D>::IsEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElement4)->put_IsEnabled(value));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapElementClickEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementClickEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapElementClickEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementClickEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement> consume_Windows_UI_Xaml_Controls_Maps_IMapElementClickEventArgs<D>::MapElements() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementClickEventArgs)->get_MapElements(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapElement consume_Windows_UI_Xaml_Controls_Maps_IMapElementFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::MapElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapElementPointerEnteredEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementPointerEnteredEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapElementPointerEnteredEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementPointerEnteredEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapElement consume_Windows_UI_Xaml_Controls_Maps_IMapElementPointerEnteredEventArgs<D>::MapElement() const
{
    Windows::UI::Xaml::Controls::Maps::MapElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementPointerEnteredEventArgs)->get_MapElement(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapElementPointerExitedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementPointerExitedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapElementPointerExitedEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementPointerExitedEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapElement consume_Windows_UI_Xaml_Controls_Maps_IMapElementPointerExitedEventArgs<D>::MapElement() const
{
    Windows::UI::Xaml::Controls::Maps::MapElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementPointerExitedEventArgs)->get_MapElement(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElementStatics<D>::ZIndexProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementStatics)->get_ZIndexProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElementStatics<D>::VisibleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementStatics)->get_VisibleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElementStatics2<D>::MapTabIndexProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementStatics2)->get_MapTabIndexProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElementStatics3<D>::MapStyleSheetEntryProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementStatics3)->get_MapStyleSheetEntryProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElementStatics3<D>::MapStyleSheetEntryStateProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementStatics3)->get_MapStyleSheetEntryStateProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElementStatics3<D>::TagProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementStatics3)->get_TagProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElementStatics4<D>::IsEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementStatics4)->get_IsEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement> consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElements() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayer)->get_MapElements(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElements(param::vector<Windows::UI::Xaml::Controls::Maps::MapElement> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayer)->put_MapElements(get_abi(value)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementClick(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerClickEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayer)->add_MapElementClick(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementClick_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementClick(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerClickEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapElementClick_revoker>(this, MapElementClick(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementClick(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayer)->remove_MapElementClick(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementPointerEntered(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerEnteredEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayer)->add_MapElementPointerEntered(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementPointerEntered_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementPointerEntered(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerEnteredEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapElementPointerEntered_revoker>(this, MapElementPointerEntered(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementPointerEntered(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayer)->remove_MapElementPointerEntered(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementPointerExited(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerExitedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayer)->add_MapElementPointerExited(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementPointerExited_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementPointerExited(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerExitedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapElementPointerExited_revoker>(this, MapElementPointerExited(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapElementPointerExited(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayer)->remove_MapElementPointerExited(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapContextRequested(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerContextRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayer)->add_MapContextRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapContextRequested_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapContextRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerContextRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, MapContextRequested_revoker>(this, MapContextRequested(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayer<D>::MapContextRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayer)->remove_MapContextRequested(get_abi(token)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerClickEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerClickEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerClickEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerClickEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement> consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerClickEventArgs<D>::MapElements() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerClickEventArgs)->get_MapElements(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerContextRequestedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerContextRequestedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerContextRequestedEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerContextRequestedEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement> consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerContextRequestedEventArgs<D>::MapElements() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerContextRequestedEventArgs)->get_MapElements(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerPointerEnteredEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerEnteredEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerPointerEnteredEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerEnteredEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapElement consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerPointerEnteredEventArgs<D>::MapElement() const
{
    Windows::UI::Xaml::Controls::Maps::MapElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerEnteredEventArgs)->get_MapElement(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerPointerExitedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerExitedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerPointerExitedEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerExitedEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapElement consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerPointerExitedEventArgs<D>::MapElement() const
{
    Windows::UI::Xaml::Controls::Maps::MapElement value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerExitedEventArgs)->get_MapElement(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapElementsLayerStatics<D>::MapElementsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapElementsLayerStatics)->get_MapElementsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapIcon<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIcon)->get_Location(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapIcon<D>::Location(Windows::Devices::Geolocation::Geopoint const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIcon)->put_Location(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapIcon<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIcon)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapIcon<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIcon)->put_Title(get_abi(value)));
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapIcon<D>::NormalizedAnchorPoint() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIcon)->get_NormalizedAnchorPoint(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapIcon<D>::NormalizedAnchorPoint(Windows::Foundation::Point const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIcon)->put_NormalizedAnchorPoint(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_UI_Xaml_Controls_Maps_IMapIcon<D>::Image() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIcon)->get_Image(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapIcon<D>::Image(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIcon)->put_Image(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior consume_Windows_UI_Xaml_Controls_Maps_IMapIcon2<D>::CollisionBehaviorDesired() const
{
    Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIcon2)->get_CollisionBehaviorDesired(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapIcon2<D>::CollisionBehaviorDesired(Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIcon2)->put_CollisionBehaviorDesired(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapIconStatics<D>::LocationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIconStatics)->get_LocationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapIconStatics<D>::TitleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIconStatics)->get_TitleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapIconStatics<D>::NormalizedAnchorPointProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIconStatics)->get_NormalizedAnchorPointProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapIconStatics2<D>::CollisionBehaviorDesiredProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapIconStatics2)->get_CollisionBehaviorDesiredProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapInputEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapInputEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapInputEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapInputEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Controls_Maps_IMapItemsControl<D>::ItemsSource() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapItemsControl)->get_ItemsSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapItemsControl<D>::ItemsSource(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapItemsControl)->put_ItemsSource(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> consume_Windows_UI_Xaml_Controls_Maps_IMapItemsControl<D>::Items() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapItemsControl)->get_Items(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DataTemplate consume_Windows_UI_Xaml_Controls_Maps_IMapItemsControl<D>::ItemTemplate() const
{
    Windows::UI::Xaml::DataTemplate value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapItemsControl)->get_ItemTemplate(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapItemsControl<D>::ItemTemplate(Windows::UI::Xaml::DataTemplate const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapItemsControl)->put_ItemTemplate(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapItemsControlStatics<D>::ItemsSourceProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapItemsControlStatics)->get_ItemsSourceProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapItemsControlStatics<D>::ItemsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapItemsControlStatics)->get_ItemsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapItemsControlStatics<D>::ItemTemplateProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapItemsControlStatics)->get_ItemTemplateProperty(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapLayer<D>::MapTabIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapLayer)->get_MapTabIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapLayer<D>::MapTabIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapLayer)->put_MapTabIndex(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapLayer<D>::Visible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapLayer)->get_Visible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapLayer<D>::Visible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapLayer)->put_Visible(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapLayer<D>::ZIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapLayer)->get_ZIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapLayer<D>::ZIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapLayer)->put_ZIndex(value));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapLayer consume_Windows_UI_Xaml_Controls_Maps_IMapLayerFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::MapLayer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapLayerFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapLayerStatics<D>::MapTabIndexProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapLayerStatics)->get_MapTabIndexProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapLayerStatics<D>::VisibleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapLayerStatics)->get_VisibleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapLayerStatics<D>::ZIndexProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapLayerStatics)->get_ZIndexProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapModel3D consume_Windows_UI_Xaml_Controls_Maps_IMapModel3DFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::MapModel3D value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapModel3DFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::MapModel3D> consume_Windows_UI_Xaml_Controls_Maps_IMapModel3DStatics<D>::CreateFrom3MFAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& source) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::MapModel3D> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapModel3DStatics)->CreateFrom3MFAsync(get_abi(source), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::MapModel3D> consume_Windows_UI_Xaml_Controls_Maps_IMapModel3DStatics<D>::CreateFrom3MFAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& source, Windows::UI::Xaml::Controls::Maps::MapModel3DShadingOption const& shadingOption) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::MapModel3D> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapModel3DStatics)->CreateFrom3MFWithShadingOptionAsync(get_abi(source), get_abi(shadingOption), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Devices::Geolocation::Geopath consume_Windows_UI_Xaml_Controls_Maps_IMapPolygon<D>::Path() const
{
    Windows::Devices::Geolocation::Geopath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygon)->get_Path(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapPolygon<D>::Path(Windows::Devices::Geolocation::Geopath const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygon)->put_Path(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Controls_Maps_IMapPolygon<D>::StrokeColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygon)->get_StrokeColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapPolygon<D>::StrokeColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygon)->put_StrokeColor(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapPolygon<D>::StrokeThickness() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygon)->get_StrokeThickness(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapPolygon<D>::StrokeThickness(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygon)->put_StrokeThickness(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapPolygon<D>::StrokeDashed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygon)->get_StrokeDashed(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapPolygon<D>::StrokeDashed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygon)->put_StrokeDashed(value));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Controls_Maps_IMapPolygon<D>::FillColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygon)->get_FillColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapPolygon<D>::FillColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygon)->put_FillColor(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Devices::Geolocation::Geopath> consume_Windows_UI_Xaml_Controls_Maps_IMapPolygon2<D>::Paths() const
{
    Windows::Foundation::Collections::IVector<Windows::Devices::Geolocation::Geopath> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygon2)->get_Paths(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapPolygonStatics<D>::PathProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygonStatics)->get_PathProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapPolygonStatics<D>::StrokeThicknessProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygonStatics)->get_StrokeThicknessProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapPolygonStatics<D>::StrokeDashedProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolygonStatics)->get_StrokeDashedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopath consume_Windows_UI_Xaml_Controls_Maps_IMapPolyline<D>::Path() const
{
    Windows::Devices::Geolocation::Geopath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolyline)->get_Path(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapPolyline<D>::Path(Windows::Devices::Geolocation::Geopath const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolyline)->put_Path(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Controls_Maps_IMapPolyline<D>::StrokeColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolyline)->get_StrokeColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapPolyline<D>::StrokeColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolyline)->put_StrokeColor(get_abi(value)));
}

template <typename D> double consume_Windows_UI_Xaml_Controls_Maps_IMapPolyline<D>::StrokeThickness() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolyline)->get_StrokeThickness(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapPolyline<D>::StrokeThickness(double value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolyline)->put_StrokeThickness(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapPolyline<D>::StrokeDashed() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolyline)->get_StrokeDashed(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapPolyline<D>::StrokeDashed(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolyline)->put_StrokeDashed(value));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapPolylineStatics<D>::PathProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolylineStatics)->get_PathProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapPolylineStatics<D>::StrokeDashedProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapPolylineStatics)->get_StrokeDashedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Xaml_Controls_Maps_IMapRightTappedEventArgs<D>::Position() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapRightTappedEventArgs)->get_Position(put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IMapRightTappedEventArgs<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapRightTappedEventArgs)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Controls_Maps_IMapRouteView<D>::RouteColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapRouteView)->get_RouteColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapRouteView<D>::RouteColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapRouteView)->put_RouteColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_Xaml_Controls_Maps_IMapRouteView<D>::OutlineColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapRouteView)->get_OutlineColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapRouteView<D>::OutlineColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapRouteView)->put_OutlineColor(get_abi(value)));
}

template <typename D> Windows::Services::Maps::MapRoute consume_Windows_UI_Xaml_Controls_Maps_IMapRouteView<D>::Route() const
{
    Windows::Services::Maps::MapRoute value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapRouteView)->get_Route(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapRouteView consume_Windows_UI_Xaml_Controls_Maps_IMapRouteViewFactory<D>::CreateInstanceWithMapRoute(Windows::Services::Maps::MapRoute const& route, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::MapRouteView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapRouteViewFactory)->CreateInstanceWithMapRoute(get_abi(route), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCamera consume_Windows_UI_Xaml_Controls_Maps_IMapScene<D>::TargetCamera() const
{
    Windows::UI::Xaml::Controls::Maps::MapCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapScene)->get_TargetCamera(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Controls_Maps_IMapScene<D>::TargetCameraChanged(Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapScene, Windows::UI::Xaml::Controls::Maps::MapTargetCameraChangedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapScene)->add_TargetCameraChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Controls_Maps_IMapScene<D>::TargetCameraChanged_revoker consume_Windows_UI_Xaml_Controls_Maps_IMapScene<D>::TargetCameraChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapScene, Windows::UI::Xaml::Controls::Maps::MapTargetCameraChangedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, TargetCameraChanged_revoker>(this, TargetCameraChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapScene<D>::TargetCameraChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapScene)->remove_TargetCameraChanged(get_abi(token)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapScene consume_Windows_UI_Xaml_Controls_Maps_IMapSceneStatics<D>::CreateFromBoundingBox(Windows::Devices::Geolocation::GeoboundingBox const& bounds) const
{
    Windows::UI::Xaml::Controls::Maps::MapScene result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapSceneStatics)->CreateFromBoundingBox(get_abi(bounds), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapScene consume_Windows_UI_Xaml_Controls_Maps_IMapSceneStatics<D>::CreateFromBoundingBox(Windows::Devices::Geolocation::GeoboundingBox const& bounds, double headingInDegrees, double pitchInDegrees) const
{
    Windows::UI::Xaml::Controls::Maps::MapScene result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapSceneStatics)->CreateFromBoundingBoxWithHeadingAndPitch(get_abi(bounds), headingInDegrees, pitchInDegrees, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapScene consume_Windows_UI_Xaml_Controls_Maps_IMapSceneStatics<D>::CreateFromCamera(Windows::UI::Xaml::Controls::Maps::MapCamera const& camera) const
{
    Windows::UI::Xaml::Controls::Maps::MapScene result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapSceneStatics)->CreateFromCamera(get_abi(camera), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapScene consume_Windows_UI_Xaml_Controls_Maps_IMapSceneStatics<D>::CreateFromLocation(Windows::Devices::Geolocation::Geopoint const& location) const
{
    Windows::UI::Xaml::Controls::Maps::MapScene result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapSceneStatics)->CreateFromLocation(get_abi(location), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapScene consume_Windows_UI_Xaml_Controls_Maps_IMapSceneStatics<D>::CreateFromLocation(Windows::Devices::Geolocation::Geopoint const& location, double headingInDegrees, double pitchInDegrees) const
{
    Windows::UI::Xaml::Controls::Maps::MapScene result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapSceneStatics)->CreateFromLocationWithHeadingAndPitch(get_abi(location), headingInDegrees, pitchInDegrees, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapScene consume_Windows_UI_Xaml_Controls_Maps_IMapSceneStatics<D>::CreateFromLocationAndRadius(Windows::Devices::Geolocation::Geopoint const& location, double radiusInMeters) const
{
    Windows::UI::Xaml::Controls::Maps::MapScene result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapSceneStatics)->CreateFromLocationAndRadius(get_abi(location), radiusInMeters, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapScene consume_Windows_UI_Xaml_Controls_Maps_IMapSceneStatics<D>::CreateFromLocationAndRadius(Windows::Devices::Geolocation::Geopoint const& location, double radiusInMeters, double headingInDegrees, double pitchInDegrees) const
{
    Windows::UI::Xaml::Controls::Maps::MapScene result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapSceneStatics)->CreateFromLocationAndRadiusWithHeadingAndPitch(get_abi(location), radiusInMeters, headingInDegrees, pitchInDegrees, put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapScene consume_Windows_UI_Xaml_Controls_Maps_IMapSceneStatics<D>::CreateFromLocations(param::iterable<Windows::Devices::Geolocation::Geopoint> const& locations) const
{
    Windows::UI::Xaml::Controls::Maps::MapScene result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapSceneStatics)->CreateFromLocations(get_abi(locations), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapScene consume_Windows_UI_Xaml_Controls_Maps_IMapSceneStatics<D>::CreateFromLocations(param::iterable<Windows::Devices::Geolocation::Geopoint> const& locations, double headingInDegrees, double pitchInDegrees) const
{
    Windows::UI::Xaml::Controls::Maps::MapScene result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapSceneStatics)->CreateFromLocationsWithHeadingAndPitch(get_abi(locations), headingInDegrees, pitchInDegrees, put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Area() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Area(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Airport() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Airport(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Cemetery() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Cemetery(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Continent() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Continent(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Education() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Education(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::IndigenousPeoplesReserve() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_IndigenousPeoplesReserve(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Island() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Island(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Medical() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Medical(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Military() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Military(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Nautical() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Nautical(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Neighborhood() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Neighborhood(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Runway() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Runway(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Sand() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Sand(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::ShoppingCenter() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_ShoppingCenter(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Stadium() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Stadium(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Vegetation() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Vegetation(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Forest() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Forest(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::GolfCourse() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_GolfCourse(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Park() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Park(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::PlayingField() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_PlayingField(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Reserve() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Reserve(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Point() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Point(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::NaturalPoint() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_NaturalPoint(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Peak() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Peak(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::VolcanicPeak() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_VolcanicPeak(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::WaterPoint() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_WaterPoint(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::PointOfInterest() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_PointOfInterest(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Business() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Business(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::FoodPoint() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_FoodPoint(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::PopulatedPlace() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_PopulatedPlace(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Capital() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Capital(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::AdminDistrictCapital() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_AdminDistrictCapital(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::CountryRegionCapital() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_CountryRegionCapital(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::RoadShield() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_RoadShield(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::RoadExit() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_RoadExit(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Transit() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Transit(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Political() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Political(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::CountryRegion() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_CountryRegion(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::AdminDistrict() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_AdminDistrict(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::District() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_District(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Structure() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Structure(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Building() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Building(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::EducationBuilding() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_EducationBuilding(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::MedicalBuilding() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_MedicalBuilding(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::TransitBuilding() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_TransitBuilding(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Transportation() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Transportation(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Road() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Road(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::ControlledAccessHighway() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_ControlledAccessHighway(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::HighSpeedRamp() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_HighSpeedRamp(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Highway() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Highway(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::MajorRoad() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_MajorRoad(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::ArterialRoad() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_ArterialRoad(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Street() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Street(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Ramp() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Ramp(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::UnpavedStreet() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_UnpavedStreet(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::TollRoad() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_TollRoad(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Railway() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Railway(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Trail() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Trail(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::WaterRoute() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_WaterRoute(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::Water() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_Water(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::River() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_River(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::RouteLine() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_RouteLine(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::WalkingRoute() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_WalkingRoute(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntriesStatics<D>::DrivingRoute() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics)->get_DrivingRoute(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntryStatesStatics<D>::Disabled() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntryStatesStatics)->get_Disabled(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntryStatesStatics<D>::Hover() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntryStatesStatics)->get_Hover(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetEntryStatesStatics<D>::Selected() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntryStatesStatics)->get_Selected(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapStyleSheet consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetStatics<D>::Aerial() const
{
    Windows::UI::Xaml::Controls::Maps::MapStyleSheet result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics)->Aerial(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapStyleSheet consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetStatics<D>::AerialWithOverlay() const
{
    Windows::UI::Xaml::Controls::Maps::MapStyleSheet result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics)->AerialWithOverlay(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapStyleSheet consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetStatics<D>::RoadLight() const
{
    Windows::UI::Xaml::Controls::Maps::MapStyleSheet result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics)->RoadLight(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapStyleSheet consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetStatics<D>::RoadDark() const
{
    Windows::UI::Xaml::Controls::Maps::MapStyleSheet result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics)->RoadDark(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapStyleSheet consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetStatics<D>::RoadHighContrastLight() const
{
    Windows::UI::Xaml::Controls::Maps::MapStyleSheet result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics)->RoadHighContrastLight(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapStyleSheet consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetStatics<D>::RoadHighContrastDark() const
{
    Windows::UI::Xaml::Controls::Maps::MapStyleSheet result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics)->RoadHighContrastDark(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapStyleSheet consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetStatics<D>::Combine(param::iterable<Windows::UI::Xaml::Controls::Maps::MapStyleSheet> const& styleSheets) const
{
    Windows::UI::Xaml::Controls::Maps::MapStyleSheet result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics)->Combine(get_abi(styleSheets), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapStyleSheet consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetStatics<D>::ParseFromJson(param::hstring const& styleAsJson) const
{
    Windows::UI::Xaml::Controls::Maps::MapStyleSheet result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics)->ParseFromJson(get_abi(styleAsJson), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapStyleSheetStatics<D>::TryParseFromJson(param::hstring const& styleAsJson, Windows::UI::Xaml::Controls::Maps::MapStyleSheet& styleSheet) const
{
    bool returnValue{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics)->TryParseFromJson(get_abi(styleAsJson), put_abi(styleSheet), &returnValue));
    return returnValue;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCamera consume_Windows_UI_Xaml_Controls_Maps_IMapTargetCameraChangedEventArgs<D>::Camera() const
{
    Windows::UI::Xaml::Controls::Maps::MapCamera value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTargetCameraChangedEventArgs)->get_Camera(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason consume_Windows_UI_Xaml_Controls_Maps_IMapTargetCameraChangedEventArgs2<D>::ChangeReason() const
{
    Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTargetCameraChangedEventArgs2)->get_ChangeReason(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamReference consume_Windows_UI_Xaml_Controls_Maps_IMapTileBitmapRequest<D>::PixelData() const
{
    Windows::Storage::Streams::IRandomAccessStreamReference value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequest)->get_PixelData(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileBitmapRequest<D>::PixelData(Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequest)->put_PixelData(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestDeferral consume_Windows_UI_Xaml_Controls_Maps_IMapTileBitmapRequest<D>::GetDeferral() const
{
    Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestDeferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequest)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileBitmapRequestDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestDeferral)->Complete());
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapTileBitmapRequestedEventArgs<D>::X() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs)->get_X(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapTileBitmapRequestedEventArgs<D>::Y() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs)->get_Y(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapTileBitmapRequestedEventArgs<D>::ZoomLevel() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs)->get_ZoomLevel(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequest consume_Windows_UI_Xaml_Controls_Maps_IMapTileBitmapRequestedEventArgs<D>::Request() const
{
    Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapTileBitmapRequestedEventArgs2<D>::FrameIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs2)->get_FrameIndex(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileDataSource consume_Windows_UI_Xaml_Controls_Maps_IMapTileDataSourceFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::MapTileDataSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileDataSourceFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileDataSource consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::DataSource() const
{
    Windows::UI::Xaml::Controls::Maps::MapTileDataSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->get_DataSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::DataSource(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->put_DataSource(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileLayer consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::Layer() const
{
    Windows::UI::Xaml::Controls::Maps::MapTileLayer value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->get_Layer(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::Layer(Windows::UI::Xaml::Controls::Maps::MapTileLayer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->put_Layer(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::ZoomLevelRange() const
{
    Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->get_ZoomLevelRange(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::ZoomLevelRange(Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->put_ZoomLevelRange(get_abi(value)));
}

template <typename D> Windows::Devices::Geolocation::GeoboundingBox consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::Bounds() const
{
    Windows::Devices::Geolocation::GeoboundingBox value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->get_Bounds(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::Bounds(Windows::Devices::Geolocation::GeoboundingBox const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->put_Bounds(get_abi(value)));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::AllowOverstretch() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->get_AllowOverstretch(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::AllowOverstretch(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->put_AllowOverstretch(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::IsFadingEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->get_IsFadingEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::IsFadingEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->put_IsFadingEnabled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::IsTransparencyEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->get_IsTransparencyEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::IsTransparencyEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->put_IsTransparencyEnabled(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::IsRetryEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->get_IsRetryEnabled(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::IsRetryEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->put_IsRetryEnabled(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::ZIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->get_ZIndex(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::ZIndex(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->put_ZIndex(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::TilePixelSize() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->get_TilePixelSize(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::TilePixelSize(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->put_TilePixelSize(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::Visible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->get_Visible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource<D>::Visible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource)->put_Visible(value));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileAnimationState consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource2<D>::AnimationState() const
{
    Windows::UI::Xaml::Controls::Maps::MapTileAnimationState value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource2)->get_AnimationState(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource2<D>::AutoPlay() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource2)->get_AutoPlay(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource2<D>::AutoPlay(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource2)->put_AutoPlay(value));
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource2<D>::FrameCount() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource2)->get_FrameCount(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource2<D>::FrameCount(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource2)->put_FrameCount(value));
}

template <typename D> Windows::Foundation::TimeSpan consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource2<D>::FrameDuration() const
{
    Windows::Foundation::TimeSpan value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource2)->get_FrameDuration(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource2<D>::FrameDuration(Windows::Foundation::TimeSpan const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource2)->put_FrameDuration(get_abi(value)));
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource2<D>::Pause() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource2)->Pause());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource2<D>::Play() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource2)->Play());
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileSource2<D>::Stop() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSource2)->Stop());
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileSource consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::MapTileSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileSource consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceFactory<D>::CreateInstanceWithDataSource(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::MapTileSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory)->CreateInstanceWithDataSource(get_abi(dataSource), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileSource consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceFactory<D>::CreateInstanceWithDataSourceAndZoomRange(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const& zoomLevelRange, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::MapTileSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory)->CreateInstanceWithDataSourceAndZoomRange(get_abi(dataSource), get_abi(zoomLevelRange), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileSource consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceFactory<D>::CreateInstanceWithDataSourceZoomRangeAndBounds(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const& zoomLevelRange, Windows::Devices::Geolocation::GeoboundingBox const& bounds, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::MapTileSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory)->CreateInstanceWithDataSourceZoomRangeAndBounds(get_abi(dataSource), get_abi(zoomLevelRange), get_abi(bounds), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileSource consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceFactory<D>::CreateInstanceWithDataSourceZoomRangeBoundsAndTileSize(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const& zoomLevelRange, Windows::Devices::Geolocation::GeoboundingBox const& bounds, int32_t tileSizeInPixels, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Controls::Maps::MapTileSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory)->CreateInstanceWithDataSourceZoomRangeBoundsAndTileSize(get_abi(dataSource), get_abi(zoomLevelRange), get_abi(bounds), tileSizeInPixels, get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics<D>::DataSourceProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics)->get_DataSourceProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics<D>::LayerProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics)->get_LayerProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics<D>::ZoomLevelRangeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics)->get_ZoomLevelRangeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics<D>::BoundsProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics)->get_BoundsProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics<D>::AllowOverstretchProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics)->get_AllowOverstretchProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics<D>::IsFadingEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics)->get_IsFadingEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics<D>::IsTransparencyEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics)->get_IsTransparencyEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics<D>::IsRetryEnabledProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics)->get_IsRetryEnabledProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics<D>::ZIndexProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics)->get_ZIndexProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics<D>::TilePixelSizeProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics)->get_TilePixelSizeProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics<D>::VisibleProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics)->get_VisibleProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics2<D>::AnimationStateProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2)->get_AnimationStateProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics2<D>::AutoPlayProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2)->get_AutoPlayProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics2<D>::FrameCountProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2)->get_FrameCountProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Controls_Maps_IMapTileSourceStatics2<D>::FrameDurationProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2)->get_FrameDurationProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_Xaml_Controls_Maps_IMapTileUriRequest<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileUriRequest)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileUriRequest<D>::Uri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileUriRequest)->put_Uri(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileUriRequestDeferral consume_Windows_UI_Xaml_Controls_Maps_IMapTileUriRequest<D>::GetDeferral() const
{
    Windows::UI::Xaml::Controls::Maps::MapTileUriRequestDeferral result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileUriRequest)->GetDeferral(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IMapTileUriRequestDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestDeferral)->Complete());
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapTileUriRequestedEventArgs<D>::X() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs)->get_X(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapTileUriRequestedEventArgs<D>::Y() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs)->get_Y(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapTileUriRequestedEventArgs<D>::ZoomLevel() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs)->get_ZoomLevel(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::MapTileUriRequest consume_Windows_UI_Xaml_Controls_Maps_IMapTileUriRequestedEventArgs<D>::Request() const
{
    Windows::UI::Xaml::Controls::Maps::MapTileUriRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Controls_Maps_IMapTileUriRequestedEventArgs2<D>::FrameIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs2)->get_FrameIndex(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::AddressTextVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->get_AddressTextVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::AddressTextVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->put_AddressTextVisible(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::CursorVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->get_CursorVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::CursorVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->put_CursorVisible(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::OverviewMapVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->get_OverviewMapVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::OverviewMapVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->put_OverviewMapVisible(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::StreetLabelsVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->get_StreetLabelsVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::StreetLabelsVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->put_StreetLabelsVisible(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::ExitButtonVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->get_ExitButtonVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::ExitButtonVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->put_ExitButtonVisible(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::ZoomButtonsVisible() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->get_ZoomButtonsVisible(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperience<D>::ZoomButtonsVisible(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperience)->put_ZoomButtonsVisible(value));
}

template <typename D> Windows::UI::Xaml::Controls::Maps::StreetsideExperience consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperienceFactory<D>::CreateInstanceWithPanorama(Windows::UI::Xaml::Controls::Maps::StreetsidePanorama const& panorama) const
{
    Windows::UI::Xaml::Controls::Maps::StreetsideExperience value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperienceFactory)->CreateInstanceWithPanorama(get_abi(panorama), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Controls::Maps::StreetsideExperience consume_Windows_UI_Xaml_Controls_Maps_IStreetsideExperienceFactory<D>::CreateInstanceWithPanoramaHeadingPitchAndFieldOfView(Windows::UI::Xaml::Controls::Maps::StreetsidePanorama const& panorama, double headingInDegrees, double pitchInDegrees, double fieldOfViewInDegrees) const
{
    Windows::UI::Xaml::Controls::Maps::StreetsideExperience value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsideExperienceFactory)->CreateInstanceWithPanoramaHeadingPitchAndFieldOfView(get_abi(panorama), headingInDegrees, pitchInDegrees, fieldOfViewInDegrees, put_abi(value)));
    return value;
}

template <typename D> Windows::Devices::Geolocation::Geopoint consume_Windows_UI_Xaml_Controls_Maps_IStreetsidePanorama<D>::Location() const
{
    Windows::Devices::Geolocation::Geopoint value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsidePanorama)->get_Location(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama> consume_Windows_UI_Xaml_Controls_Maps_IStreetsidePanoramaStatics<D>::FindNearbyAsync(Windows::Devices::Geolocation::Geopoint const& location) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsidePanoramaStatics)->FindNearbyWithLocationAsync(get_abi(location), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama> consume_Windows_UI_Xaml_Controls_Maps_IStreetsidePanoramaStatics<D>::FindNearbyAsync(Windows::Devices::Geolocation::Geopoint const& location, double radiusInMeters) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Controls::Maps::IStreetsidePanoramaStatics)->FindNearbyWithLocationAndRadiusAsync(get_abi(location), radiusInMeters, put_abi(operation)));
    return operation;
}

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSource> : produce_base<D, Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSource>
{
    int32_t WINRT_CALL add_BitmapRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BitmapRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BitmapRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BitmapRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BitmapRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BitmapRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSourceFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSourceFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource>
{
    int32_t WINRT_CALL get_UriFormatString(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriFormatString, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UriFormatString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UriFormatString(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriFormatString, WINRT_WRAP(void), hstring const&);
            this->shim().UriFormatString(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdditionalRequestHeaders(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdditionalRequestHeaders, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().AdditionalRequestHeaders());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowCaching(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowCaching, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowCaching());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowCaching(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowCaching, WINRT_WRAP(void), bool);
            this->shim().AllowCaching(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_UriRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileUriRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().UriRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileUriRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UriRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UriRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UriRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSourceFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSourceFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithUriFormatString(void* uriFormatString, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithUriFormatString, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource), hstring const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource>(this->shim().CreateInstanceWithUriFormatString(*reinterpret_cast<hstring const*>(&uriFormatString), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSource> : produce_base<D, Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSource>
{
    int32_t WINRT_CALL get_UriFormatString(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriFormatString, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UriFormatString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UriFormatString(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriFormatString, WINRT_WRAP(void), hstring const&);
            this->shim().UriFormatString(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_UriRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UriRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileUriRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().UriRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileUriRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UriRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UriRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UriRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSourceFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSourceFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithUriFormatString(void* uriFormatString, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithUriFormatString, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource), hstring const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource>(this->shim().CreateInstanceWithUriFormatString(*reinterpret_cast<hstring const*>(&uriFormatString), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangedEventArgs>
{
    int32_t WINRT_CALL get_Camera(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Camera, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCamera));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCamera>(this->shim().Camera());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangedEventArgs2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangedEventArgs2>
{
    int32_t WINRT_CALL get_ChangeReason(Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeReason, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason>(this->shim().ChangeReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangingEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangingEventArgs>
{
    int32_t WINRT_CALL get_Camera(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Camera, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCamera));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCamera>(this->shim().Camera());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangingEventArgs2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangingEventArgs2>
{
    int32_t WINRT_CALL get_ChangeReason(Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeReason, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason>(this->shim().ChangeReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapBillboard> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapBillboard>
{
    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Location(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(void), Windows::Devices::Geolocation::Geopoint const&);
            this->shim().Location(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalizedAnchorPoint(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedAnchorPoint, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().NormalizedAnchorPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NormalizedAnchorPoint(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedAnchorPoint, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().NormalizedAnchorPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Image(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Image, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Image());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Image(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Image, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Image(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CollisionBehaviorDesired(Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CollisionBehaviorDesired, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior>(this->shim().CollisionBehaviorDesired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CollisionBehaviorDesired(Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CollisionBehaviorDesired, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior const&);
            this->shim().CollisionBehaviorDesired(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReferenceCamera(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReferenceCamera, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCamera));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCamera>(this->shim().ReferenceCamera());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapBillboardFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapBillboardFactory>
{
    int32_t WINRT_CALL CreateInstanceFromCamera(void* camera, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceFromCamera, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapBillboard), Windows::UI::Xaml::Controls::Maps::MapCamera const&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapBillboard>(this->shim().CreateInstanceFromCamera(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapCamera const*>(&camera)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapBillboardStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapBillboardStatics>
{
    int32_t WINRT_CALL get_LocationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LocationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalizedAnchorPointProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedAnchorPointProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().NormalizedAnchorPointProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CollisionBehaviorDesiredProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CollisionBehaviorDesiredProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CollisionBehaviorDesiredProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapCamera> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapCamera>
{
    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Location(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(void), Windows::Devices::Geolocation::Geopoint const&);
            this->shim().Location(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Heading(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Heading, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Heading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Heading(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Heading, WINRT_WRAP(void), double);
            this->shim().Heading(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pitch(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pitch, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Pitch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Pitch(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pitch, WINRT_WRAP(void), double);
            this->shim().Pitch(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Roll(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Roll, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Roll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Roll(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Roll, WINRT_WRAP(void), double);
            this->shim().Roll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FieldOfView(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FieldOfView, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().FieldOfView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FieldOfView(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FieldOfView, WINRT_WRAP(void), double);
            this->shim().FieldOfView(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapCameraFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapCameraFactory>
{
    int32_t WINRT_CALL CreateInstanceWithLocation(void* location, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithLocation, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCamera), Windows::Devices::Geolocation::Geopoint const&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCamera>(this->shim().CreateInstanceWithLocation(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithLocationAndHeading(void* location, double headingInDegrees, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithLocationAndHeading, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCamera), Windows::Devices::Geolocation::Geopoint const&, double);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCamera>(this->shim().CreateInstanceWithLocationAndHeading(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location), headingInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithLocationHeadingAndPitch(void* location, double headingInDegrees, double pitchInDegrees, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithLocationHeadingAndPitch, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCamera), Windows::Devices::Geolocation::Geopoint const&, double, double);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCamera>(this->shim().CreateInstanceWithLocationHeadingAndPitch(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location), headingInDegrees, pitchInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithLocationHeadingPitchRollAndFieldOfView(void* location, double headingInDegrees, double pitchInDegrees, double rollInDegrees, double fieldOfViewInDegrees, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithLocationHeadingPitchRollAndFieldOfView, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCamera), Windows::Devices::Geolocation::Geopoint const&, double, double, double, double);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCamera>(this->shim().CreateInstanceWithLocationHeadingPitchRollAndFieldOfView(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location), headingInDegrees, pitchInDegrees, rollInDegrees, fieldOfViewInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapContextRequestedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapContextRequestedEventArgs>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapElements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElements, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement>>(this->shim().MapElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControl> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControl>
{
    int32_t WINRT_CALL get_Center(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Center());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Center(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(void), Windows::Devices::Geolocation::Geopoint const&);
            this->shim().Center(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Children(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Children, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject>>(this->shim().Children());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorScheme(Windows::UI::Xaml::Controls::Maps::MapColorScheme* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorScheme, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapColorScheme));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapColorScheme>(this->shim().ColorScheme());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ColorScheme(Windows::UI::Xaml::Controls::Maps::MapColorScheme value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorScheme, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapColorScheme const&);
            this->shim().ColorScheme(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapColorScheme const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredPitch(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredPitch, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().DesiredPitch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DesiredPitch(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredPitch, WINRT_WRAP(void), double);
            this->shim().DesiredPitch(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Heading(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Heading, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Heading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Heading(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Heading, WINRT_WRAP(void), double);
            this->shim().Heading(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LandmarksVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LandmarksVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().LandmarksVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LandmarksVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LandmarksVisible, WINRT_WRAP(void), bool);
            this->shim().LandmarksVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LoadingStatus(Windows::UI::Xaml::Controls::Maps::MapLoadingStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadingStatus, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapLoadingStatus));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapLoadingStatus>(this->shim().LoadingStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapServiceToken(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapServiceToken, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MapServiceToken());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MapServiceToken(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapServiceToken, WINRT_WRAP(void), hstring const&);
            this->shim().MapServiceToken(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxZoomLevel(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxZoomLevel, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MaxZoomLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MinZoomLevel(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MinZoomLevel, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MinZoomLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PedestrianFeaturesVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PedestrianFeaturesVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().PedestrianFeaturesVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PedestrianFeaturesVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PedestrianFeaturesVisible, WINRT_WRAP(void), bool);
            this->shim().PedestrianFeaturesVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pitch(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pitch, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Pitch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Style(Windows::UI::Xaml::Controls::Maps::MapStyle* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Style, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapStyle));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapStyle>(this->shim().Style());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Style(Windows::UI::Xaml::Controls::Maps::MapStyle value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Style, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapStyle const&);
            this->shim().Style(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrafficFlowVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrafficFlowVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().TrafficFlowVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TrafficFlowVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrafficFlowVisible, WINRT_WRAP(void), bool);
            this->shim().TrafficFlowVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransformOrigin(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformOrigin, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().TransformOrigin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransformOrigin(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformOrigin, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().TransformOrigin(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WatermarkMode(Windows::UI::Xaml::Controls::Maps::MapWatermarkMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WatermarkMode, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapWatermarkMode));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapWatermarkMode>(this->shim().WatermarkMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WatermarkMode(Windows::UI::Xaml::Controls::Maps::MapWatermarkMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WatermarkMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapWatermarkMode const&);
            this->shim().WatermarkMode(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapWatermarkMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomLevel(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomLevel, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().ZoomLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ZoomLevel(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomLevel, WINRT_WRAP(void), double);
            this->shim().ZoomLevel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapElements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElements, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement>>(this->shim().MapElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Routes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Routes, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapRouteView>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapRouteView>>(this->shim().Routes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TileSources(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TileSources, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapTileSource>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapTileSource>>(this->shim().TileSources());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CenterChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CenterChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CenterChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CenterChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CenterChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_HeadingChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeadingChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().HeadingChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_HeadingChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(HeadingChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().HeadingChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_LoadingStatusChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadingStatusChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().LoadingStatusChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_LoadingStatusChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(LoadingStatusChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().LoadingStatusChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MapDoubleTapped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapDoubleTapped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapDoubleTapped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapDoubleTapped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapDoubleTapped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapDoubleTapped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MapHolding(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapHolding, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapHolding(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapHolding(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapHolding, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapHolding(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MapTapped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapTapped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapTapped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapTapped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapTapped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapTapped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_PitchChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PitchChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().PitchChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PitchChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PitchChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PitchChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_TransformOriginChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformOriginChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().TransformOriginChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TransformOriginChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TransformOriginChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TransformOriginChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ZoomLevelChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomLevelChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().ZoomLevelChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ZoomLevelChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ZoomLevelChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ZoomLevelChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL FindMapElementsAtOffset(Windows::Foundation::Point offset, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindMapElementsAtOffset, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement>), Windows::Foundation::Point const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement>>(this->shim().FindMapElementsAtOffset(*reinterpret_cast<Windows::Foundation::Point const*>(&offset)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocationFromOffset(Windows::Foundation::Point offset, void** location) noexcept final
    {
        try
        {
            *location = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocationFromOffset, WINRT_WRAP(void), Windows::Foundation::Point const&, Windows::Devices::Geolocation::Geopoint&);
            this->shim().GetLocationFromOffset(*reinterpret_cast<Windows::Foundation::Point const*>(&offset), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint*>(location));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetOffsetFromLocation(void* location, Windows::Foundation::Point* offset) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetOffsetFromLocation, WINRT_WRAP(void), Windows::Devices::Geolocation::Geopoint const&, Windows::Foundation::Point&);
            this->shim().GetOffsetFromLocation(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location), *reinterpret_cast<Windows::Foundation::Point*>(offset));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsLocationInView(void* location, bool* isInView) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsLocationInView, WINRT_WRAP(void), Windows::Devices::Geolocation::Geopoint const&, bool&);
            this->shim().IsLocationInView(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location), *isInView);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetViewBoundsAsync(void* bounds, void* margin, Windows::UI::Xaml::Controls::Maps::MapAnimationKind animation, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetViewBoundsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::Geolocation::GeoboundingBox const, Windows::Foundation::IReference<Windows::UI::Xaml::Thickness> const, Windows::UI::Xaml::Controls::Maps::MapAnimationKind const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetViewBoundsAsync(*reinterpret_cast<Windows::Devices::Geolocation::GeoboundingBox const*>(&bounds), *reinterpret_cast<Windows::Foundation::IReference<Windows::UI::Xaml::Thickness> const*>(&margin), *reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapAnimationKind const*>(&animation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetViewWithCenterAsync(void* center, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetViewAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::Geolocation::Geopoint const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetViewAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&center)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetViewWithCenterAndZoomAsync(void* center, void* zoomLevel, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetViewAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::Geolocation::Geopoint const, Windows::Foundation::IReference<double> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetViewAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&center), *reinterpret_cast<Windows::Foundation::IReference<double> const*>(&zoomLevel)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetViewWithCenterZoomHeadingAndPitchAsync(void* center, void* zoomLevel, void* heading, void* desiredPitch, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetViewAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::Geolocation::Geopoint const, Windows::Foundation::IReference<double> const, Windows::Foundation::IReference<double> const, Windows::Foundation::IReference<double> const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetViewAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&center), *reinterpret_cast<Windows::Foundation::IReference<double> const*>(&zoomLevel), *reinterpret_cast<Windows::Foundation::IReference<double> const*>(&heading), *reinterpret_cast<Windows::Foundation::IReference<double> const*>(&desiredPitch)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetViewWithCenterZoomHeadingPitchAndAnimationAsync(void* center, void* zoomLevel, void* heading, void* desiredPitch, Windows::UI::Xaml::Controls::Maps::MapAnimationKind animation, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetViewAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::Geolocation::Geopoint const, Windows::Foundation::IReference<double> const, Windows::Foundation::IReference<double> const, Windows::Foundation::IReference<double> const, Windows::UI::Xaml::Controls::Maps::MapAnimationKind const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetViewAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&center), *reinterpret_cast<Windows::Foundation::IReference<double> const*>(&zoomLevel), *reinterpret_cast<Windows::Foundation::IReference<double> const*>(&heading), *reinterpret_cast<Windows::Foundation::IReference<double> const*>(&desiredPitch), *reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapAnimationKind const*>(&animation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControl2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControl2>
{
    int32_t WINRT_CALL get_BusinessLandmarksVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusinessLandmarksVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().BusinessLandmarksVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BusinessLandmarksVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusinessLandmarksVisible, WINRT_WRAP(void), bool);
            this->shim().BusinessLandmarksVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitFeaturesVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitFeaturesVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().TransitFeaturesVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransitFeaturesVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitFeaturesVisible, WINRT_WRAP(void), bool);
            this->shim().TransitFeaturesVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PanInteractionMode(Windows::UI::Xaml::Controls::Maps::MapPanInteractionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PanInteractionMode, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapPanInteractionMode));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapPanInteractionMode>(this->shim().PanInteractionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PanInteractionMode(Windows::UI::Xaml::Controls::Maps::MapPanInteractionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PanInteractionMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapPanInteractionMode const&);
            this->shim().PanInteractionMode(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapPanInteractionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotateInteractionMode(Windows::UI::Xaml::Controls::Maps::MapInteractionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotateInteractionMode, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapInteractionMode));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapInteractionMode>(this->shim().RotateInteractionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RotateInteractionMode(Windows::UI::Xaml::Controls::Maps::MapInteractionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotateInteractionMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapInteractionMode const&);
            this->shim().RotateInteractionMode(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapInteractionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TiltInteractionMode(Windows::UI::Xaml::Controls::Maps::MapInteractionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiltInteractionMode, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapInteractionMode));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapInteractionMode>(this->shim().TiltInteractionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TiltInteractionMode(Windows::UI::Xaml::Controls::Maps::MapInteractionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiltInteractionMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapInteractionMode const&);
            this->shim().TiltInteractionMode(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapInteractionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomInteractionMode(Windows::UI::Xaml::Controls::Maps::MapInteractionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomInteractionMode, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapInteractionMode));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapInteractionMode>(this->shim().ZoomInteractionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ZoomInteractionMode(Windows::UI::Xaml::Controls::Maps::MapInteractionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomInteractionMode, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapInteractionMode const&);
            this->shim().ZoomInteractionMode(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapInteractionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Is3DSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Is3DSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Is3DSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStreetsideSupported(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStreetsideSupported, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsStreetsideSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scene(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scene, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapScene));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapScene>(this->shim().Scene());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Scene(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scene, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapScene const&);
            this->shim().Scene(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapScene const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActualCamera(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualCamera, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCamera));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCamera>(this->shim().ActualCamera());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetCamera(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetCamera, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCamera));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCamera>(this->shim().TargetCamera());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CustomExperience(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomExperience, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCustomExperience));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCustomExperience>(this->shim().CustomExperience());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CustomExperience(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomExperience, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapCustomExperience const&);
            this->shim().CustomExperience(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapCustomExperience const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MapElementClick(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElementClick, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementClickEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapElementClick(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementClickEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapElementClick(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapElementClick, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapElementClick(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MapElementPointerEntered(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElementPointerEntered, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementPointerEnteredEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapElementPointerEntered(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementPointerEnteredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapElementPointerEntered(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapElementPointerEntered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapElementPointerEntered(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MapElementPointerExited(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElementPointerExited, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementPointerExitedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapElementPointerExited(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapElementPointerExitedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapElementPointerExited(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapElementPointerExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapElementPointerExited(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ActualCameraChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualCameraChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapActualCameraChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ActualCameraChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapActualCameraChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ActualCameraChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ActualCameraChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ActualCameraChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_ActualCameraChanging(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActualCameraChanging, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapActualCameraChangingEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().ActualCameraChanging(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapActualCameraChangingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_ActualCameraChanging(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(ActualCameraChanging, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().ActualCameraChanging(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_TargetCameraChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetCameraChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapTargetCameraChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TargetCameraChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapTargetCameraChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TargetCameraChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TargetCameraChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TargetCameraChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CustomExperienceChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CustomExperienceChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapCustomExperienceChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().CustomExperienceChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapCustomExperienceChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CustomExperienceChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CustomExperienceChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CustomExperienceChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL StartContinuousRotate(double rateInDegreesPerSecond) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartContinuousRotate, WINRT_WRAP(void), double);
            this->shim().StartContinuousRotate(rateInDegreesPerSecond);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopContinuousRotate() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopContinuousRotate, WINRT_WRAP(void));
            this->shim().StopContinuousRotate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartContinuousTilt(double rateInDegreesPerSecond) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartContinuousTilt, WINRT_WRAP(void), double);
            this->shim().StartContinuousTilt(rateInDegreesPerSecond);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopContinuousTilt() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopContinuousTilt, WINRT_WRAP(void));
            this->shim().StopContinuousTilt();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartContinuousZoom(double rateOfChangePerSecond) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartContinuousZoom, WINRT_WRAP(void), double);
            this->shim().StartContinuousZoom(rateOfChangePerSecond);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopContinuousZoom() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopContinuousZoom, WINRT_WRAP(void));
            this->shim().StopContinuousZoom();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRotateAsync(double degrees, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRotateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), double);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRotateAsync(degrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRotateToAsync(double angleInDegrees, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRotateToAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), double);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRotateToAsync(angleInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryTiltAsync(double degrees, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryTiltAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), double);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryTiltAsync(degrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryTiltToAsync(double angleInDegrees, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryTiltToAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), double);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryTiltToAsync(angleInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryZoomInAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryZoomInAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryZoomInAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryZoomOutAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryZoomOutAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryZoomOutAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryZoomToAsync(double zoomLevel, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryZoomToAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), double);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryZoomToAsync(zoomLevel));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetSceneAsync(void* scene, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetSceneAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::UI::Xaml::Controls::Maps::MapScene const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetSceneAsync(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapScene const*>(&scene)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TrySetSceneWithAnimationAsync(void* scene, Windows::UI::Xaml::Controls::Maps::MapAnimationKind animationKind, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrySetSceneAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::UI::Xaml::Controls::Maps::MapScene const, Windows::UI::Xaml::Controls::Maps::MapAnimationKind const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetSceneAsync(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapScene const*>(&scene), *reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapAnimationKind const*>(&animationKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControl3> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControl3>
{
    int32_t WINRT_CALL add_MapRightTapped(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapRightTapped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapRightTappedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapRightTapped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapRightTappedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapRightTapped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapRightTapped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapRightTapped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControl4> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControl4>
{
    int32_t WINRT_CALL get_BusinessLandmarksEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusinessLandmarksEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().BusinessLandmarksEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BusinessLandmarksEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusinessLandmarksEnabled, WINRT_WRAP(void), bool);
            this->shim().BusinessLandmarksEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitFeaturesEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitFeaturesEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().TransitFeaturesEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TransitFeaturesEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitFeaturesEnabled, WINRT_WRAP(void), bool);
            this->shim().TransitFeaturesEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVisibleRegion(Windows::UI::Xaml::Controls::Maps::MapVisibleRegionKind region, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVisibleRegion, WINRT_WRAP(Windows::Devices::Geolocation::Geopath), Windows::UI::Xaml::Controls::Maps::MapVisibleRegionKind const&);
            *result = detach_from<Windows::Devices::Geolocation::Geopath>(this->shim().GetVisibleRegion(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapVisibleRegionKind const*>(&region)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControl5> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControl5>
{
    int32_t WINRT_CALL get_MapProjection(Windows::UI::Xaml::Controls::Maps::MapProjection* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapProjection, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapProjection));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapProjection>(this->shim().MapProjection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MapProjection(Windows::UI::Xaml::Controls::Maps::MapProjection value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapProjection, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapProjection const&);
            this->shim().MapProjection(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapProjection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StyleSheet(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleSheet, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapStyleSheet));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapStyleSheet>(this->shim().StyleSheet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StyleSheet(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleSheet, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapStyleSheet const&);
            this->shim().StyleSheet(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapStyleSheet const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewPadding(struct struct_Windows_UI_Xaml_Thickness* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewPadding, WINRT_WRAP(Windows::UI::Xaml::Thickness));
            *value = detach_from<Windows::UI::Xaml::Thickness>(this->shim().ViewPadding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ViewPadding(struct struct_Windows_UI_Xaml_Thickness value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewPadding, WINRT_WRAP(void), Windows::UI::Xaml::Thickness const&);
            this->shim().ViewPadding(*reinterpret_cast<Windows::UI::Xaml::Thickness const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MapContextRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapContextRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapContextRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapContextRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapContextRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapContextRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapContextRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapContextRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL FindMapElementsAtOffsetWithRadius(Windows::Foundation::Point offset, double radius, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindMapElementsAtOffset, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement>), Windows::Foundation::Point const&, double);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement>>(this->shim().FindMapElementsAtOffset(*reinterpret_cast<Windows::Foundation::Point const*>(&offset), radius));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocationFromOffsetWithReferenceSystem(Windows::Foundation::Point offset, Windows::Devices::Geolocation::AltitudeReferenceSystem desiredReferenceSystem, void** location) noexcept final
    {
        try
        {
            *location = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocationFromOffset, WINRT_WRAP(void), Windows::Foundation::Point const&, Windows::Devices::Geolocation::AltitudeReferenceSystem const&, Windows::Devices::Geolocation::Geopoint&);
            this->shim().GetLocationFromOffset(*reinterpret_cast<Windows::Foundation::Point const*>(&offset), *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&desiredReferenceSystem), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint*>(location));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StartContinuousPan(double horizontalPixelsPerSecond, double verticalPixelsPerSecond) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StartContinuousPan, WINRT_WRAP(void), double, double);
            this->shim().StartContinuousPan(horizontalPixelsPerSecond, verticalPixelsPerSecond);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL StopContinuousPan() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StopContinuousPan, WINRT_WRAP(void));
            this->shim().StopContinuousPan();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryPanAsync(double horizontalPixels, double verticalPixels, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryPanAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), double, double);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryPanAsync(horizontalPixels, verticalPixels));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryPanToAsync(void* location, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryPanToAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Devices::Geolocation::Geopoint const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryPanToAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControl6> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControl6>
{
    int32_t WINRT_CALL get_Layers(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Layers, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapLayer>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapLayer>>(this->shim().Layers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Layers(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Layers, WINRT_WRAP(void), Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapLayer> const&);
            this->shim().Layers(*reinterpret_cast<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapLayer> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetLocationFromOffset(Windows::Foundation::Point offset, void** location, bool* returnValue) noexcept final
    {
        try
        {
            *location = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetLocationFromOffset, WINRT_WRAP(bool), Windows::Foundation::Point const&, Windows::Devices::Geolocation::Geopoint&);
            *returnValue = detach_from<bool>(this->shim().TryGetLocationFromOffset(*reinterpret_cast<Windows::Foundation::Point const*>(&offset), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint*>(location)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryGetLocationFromOffsetWithReferenceSystem(Windows::Foundation::Point offset, Windows::Devices::Geolocation::AltitudeReferenceSystem desiredReferenceSystem, void** location, bool* returnValue) noexcept final
    {
        try
        {
            *location = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryGetLocationFromOffset, WINRT_WRAP(bool), Windows::Foundation::Point const&, Windows::Devices::Geolocation::AltitudeReferenceSystem const&, Windows::Devices::Geolocation::Geopoint&);
            *returnValue = detach_from<bool>(this->shim().TryGetLocationFromOffset(*reinterpret_cast<Windows::Foundation::Point const*>(&offset), *reinterpret_cast<Windows::Devices::Geolocation::AltitudeReferenceSystem const*>(&desiredReferenceSystem), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint*>(location)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControl7> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControl7>
{
    int32_t WINRT_CALL get_Region(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Region, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Region());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Region(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Region, WINRT_WRAP(void), hstring const&);
            this->shim().Region(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControl8> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControl8>
{
    int32_t WINRT_CALL get_CanTiltDown(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanTiltDown, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanTiltDown());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanTiltUp(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanTiltUp, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanTiltUp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanZoomIn(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanZoomIn, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanZoomIn());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanZoomOut(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanZoomOut, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanZoomOut());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkClickEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkClickEventArgs>
{
    int32_t WINRT_CALL get_LocalLocations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalLocations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation>>(this->shim().LocalLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkPointerEnteredEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkPointerEnteredEventArgs>
{
    int32_t WINRT_CALL get_LocalLocations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalLocations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation>>(this->shim().LocalLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkPointerExitedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkPointerExitedEventArgs>
{
    int32_t WINRT_CALL get_LocalLocations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalLocations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation>>(this->shim().LocalLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkRightTappedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkRightTappedEventArgs>
{
    int32_t WINRT_CALL get_LocalLocations(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocalLocations, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Services::Maps::LocalSearch::LocalLocation>>(this->shim().LocalLocations());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper>
{
    int32_t WINRT_CALL add_BusinessLandmarkClick(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusinessLandmarkClick, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkClickEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BusinessLandmarkClick(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkClickEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BusinessLandmarkClick(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BusinessLandmarkClick, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BusinessLandmarkClick(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_TransitFeatureClick(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitFeatureClick, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureClickEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TransitFeatureClick(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureClickEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TransitFeatureClick(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TransitFeatureClick, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TransitFeatureClick(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BusinessLandmarkRightTapped(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusinessLandmarkRightTapped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkRightTappedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BusinessLandmarkRightTapped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkRightTappedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BusinessLandmarkRightTapped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BusinessLandmarkRightTapped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BusinessLandmarkRightTapped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_TransitFeatureRightTapped(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitFeatureRightTapped, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureRightTappedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TransitFeatureRightTapped(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureRightTappedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TransitFeatureRightTapped(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TransitFeatureRightTapped, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TransitFeatureRightTapped(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2>
{
    int32_t WINRT_CALL add_BusinessLandmarkPointerEntered(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusinessLandmarkPointerEntered, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerEnteredEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BusinessLandmarkPointerEntered(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerEnteredEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BusinessLandmarkPointerEntered(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BusinessLandmarkPointerEntered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BusinessLandmarkPointerEntered(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_TransitFeaturePointerEntered(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitFeaturePointerEntered, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerEnteredEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TransitFeaturePointerEntered(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerEnteredEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TransitFeaturePointerEntered(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TransitFeaturePointerEntered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TransitFeaturePointerEntered(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_BusinessLandmarkPointerExited(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusinessLandmarkPointerExited, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerExitedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().BusinessLandmarkPointerExited(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerExitedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_BusinessLandmarkPointerExited(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(BusinessLandmarkPointerExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().BusinessLandmarkPointerExited(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_TransitFeaturePointerExited(void* value, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitFeaturePointerExited, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerExitedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TransitFeaturePointerExited(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapControl, Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerExitedEventArgs> const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TransitFeaturePointerExited(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TransitFeaturePointerExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TransitFeaturePointerExited(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperFactory>
{
    int32_t WINRT_CALL CreateInstance(void* map, void** instance) noexcept final
    {
        try
        {
            *instance = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapControlDataHelper), Windows::UI::Xaml::Controls::Maps::MapControl const&);
            *instance = detach_from<Windows::UI::Xaml::Controls::Maps::MapControlDataHelper>(this->shim().CreateInstance(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapControl const*>(&map)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperStatics>
{
    int32_t WINRT_CALL CreateMapControl(bool rasterRenderMode, void** returnValue) noexcept final
    {
        try
        {
            *returnValue = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMapControl, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapControl), bool);
            *returnValue = detach_from<Windows::UI::Xaml::Controls::Maps::MapControl>(this->shim().CreateMapControl(rasterRenderMode));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>
{
    int32_t WINRT_CALL get_CenterProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CenterProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CenterProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ChildrenProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChildrenProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ChildrenProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorSchemeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorSchemeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ColorSchemeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DesiredPitchProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DesiredPitchProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DesiredPitchProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeadingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeadingProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HeadingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LandmarksVisibleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LandmarksVisibleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LandmarksVisibleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LoadingStatusProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadingStatusProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LoadingStatusProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapServiceTokenProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapServiceTokenProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MapServiceTokenProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PedestrianFeaturesVisibleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PedestrianFeaturesVisibleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PedestrianFeaturesVisibleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PitchProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PitchProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PitchProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StyleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StyleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TrafficFlowVisibleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TrafficFlowVisibleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TrafficFlowVisibleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransformOriginProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransformOriginProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TransformOriginProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WatermarkModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WatermarkModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().WatermarkModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomLevelProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomLevelProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ZoomLevelProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapElementsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElementsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MapElementsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoutesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoutesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RoutesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TileSourcesProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TileSourcesProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TileSourcesProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LocationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LocationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetLocation(void* element, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetLocation, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().GetLocation(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetLocation(void* element, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetLocation, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::Devices::Geolocation::Geopoint const&);
            this->shim().SetLocation(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalizedAnchorPointProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedAnchorPointProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().NormalizedAnchorPointProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetNormalizedAnchorPoint(void* element, Windows::Foundation::Point* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetNormalizedAnchorPoint, WINRT_WRAP(Windows::Foundation::Point), Windows::UI::Xaml::DependencyObject const&);
            *result = detach_from<Windows::Foundation::Point>(this->shim().GetNormalizedAnchorPoint(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetNormalizedAnchorPoint(void* element, Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetNormalizedAnchorPoint, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::Foundation::Point const&);
            this->shim().SetNormalizedAnchorPoint(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics2>
{
    int32_t WINRT_CALL get_BusinessLandmarksVisibleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusinessLandmarksVisibleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().BusinessLandmarksVisibleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitFeaturesVisibleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitFeaturesVisibleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TransitFeaturesVisibleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PanInteractionModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PanInteractionModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PanInteractionModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotateInteractionModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotateInteractionModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RotateInteractionModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TiltInteractionModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TiltInteractionModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TiltInteractionModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomInteractionModeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomInteractionModeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ZoomInteractionModeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Is3DSupportedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Is3DSupportedProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().Is3DSupportedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsStreetsideSupportedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsStreetsideSupportedProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsStreetsideSupportedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SceneProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SceneProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SceneProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics4> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics4>
{
    int32_t WINRT_CALL get_BusinessLandmarksEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BusinessLandmarksEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().BusinessLandmarksEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitFeaturesEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitFeaturesEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TransitFeaturesEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics5> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics5>
{
    int32_t WINRT_CALL get_MapProjectionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapProjectionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MapProjectionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StyleSheetProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StyleSheetProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StyleSheetProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewPaddingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewPaddingProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ViewPaddingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics6> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics6>
{
    int32_t WINRT_CALL get_LayersProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LayersProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LayersProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics7> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics7>
{
    int32_t WINRT_CALL get_RegionProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RegionProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RegionProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics8> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlStatics8>
{
    int32_t WINRT_CALL get_CanTiltDownProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanTiltDownProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CanTiltDownProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanTiltUpProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanTiltUpProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CanTiltUpProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanZoomInProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanZoomInProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CanZoomInProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanZoomOutProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanZoomOutProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CanZoomOutProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureClickEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureClickEventArgs>
{
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

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitProperties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().TransitProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerEnteredEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerEnteredEventArgs>
{
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

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitProperties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().TransitProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerExitedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerExitedEventArgs>
{
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

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitProperties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().TransitProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureRightTappedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureRightTappedEventArgs>
{
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

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitProperties, WINRT_WRAP(Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IMapView<hstring, Windows::Foundation::IInspectable>>(this->shim().TransitProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapCustomExperience> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapCustomExperience>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapCustomExperienceChangedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapCustomExperienceChangedEventArgs>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapCustomExperienceFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapCustomExperienceFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCustomExperience), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCustomExperience>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElement> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElement>
{
    int32_t WINRT_CALL get_ZIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ZIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ZIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndex, WINRT_WRAP(void), int32_t);
            this->shim().ZIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Visible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Visible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(void), bool);
            this->shim().Visible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElement2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElement2>
{
    int32_t WINRT_CALL get_MapTabIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapTabIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MapTabIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MapTabIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapTabIndex, WINRT_WRAP(void), int32_t);
            this->shim().MapTabIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElement3> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElement3>
{
    int32_t WINRT_CALL get_MapStyleSheetEntry(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapStyleSheetEntry, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MapStyleSheetEntry());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MapStyleSheetEntry(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapStyleSheetEntry, WINRT_WRAP(void), hstring const&);
            this->shim().MapStyleSheetEntry(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapStyleSheetEntryState(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapStyleSheetEntryState, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MapStyleSheetEntryState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MapStyleSheetEntryState(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapStyleSheetEntryState, WINRT_WRAP(void), hstring const&);
            this->shim().MapStyleSheetEntryState(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Tag(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Tag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Tag(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Tag, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Tag(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElement3D> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElement3D>
{
    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Location(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(void), Windows::Devices::Geolocation::Geopoint const&);
            this->shim().Location(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Model(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Model, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapModel3D));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapModel3D>(this->shim().Model());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Model(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Model, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapModel3D const&);
            this->shim().Model(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapModel3D const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Heading(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Heading, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Heading());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Heading(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Heading, WINRT_WRAP(void), double);
            this->shim().Heading(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pitch(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pitch, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Pitch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Pitch(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pitch, WINRT_WRAP(void), double);
            this->shim().Pitch(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Roll(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Roll, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().Roll());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Roll(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Roll, WINRT_WRAP(void), double);
            this->shim().Roll(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Scale(Windows::Foundation::Numerics::float3* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(Windows::Foundation::Numerics::float3));
            *value = detach_from<Windows::Foundation::Numerics::float3>(this->shim().Scale());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Scale(Windows::Foundation::Numerics::float3 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Scale, WINRT_WRAP(void), Windows::Foundation::Numerics::float3 const&);
            this->shim().Scale(*reinterpret_cast<Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics>
{
    int32_t WINRT_CALL get_LocationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LocationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HeadingProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HeadingProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().HeadingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PitchProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PitchProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PitchProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RollProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RollProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().RollProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ScaleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ScaleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ScaleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElement4> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElement4>
{
    int32_t WINRT_CALL get_IsEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabled, WINRT_WRAP(void), bool);
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementClickEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementClickEventArgs>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapElements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElements, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement>>(this->shim().MapElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapElement), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapElement>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementPointerEnteredEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementPointerEnteredEventArgs>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElement, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapElement));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapElement>(this->shim().MapElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementPointerExitedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementPointerExitedEventArgs>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElement, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapElement));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapElement>(this->shim().MapElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementStatics>
{
    int32_t WINRT_CALL get_ZIndexProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndexProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ZIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VisibleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisibleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().VisibleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementStatics2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementStatics2>
{
    int32_t WINRT_CALL get_MapTabIndexProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapTabIndexProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MapTabIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementStatics3> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementStatics3>
{
    int32_t WINRT_CALL get_MapStyleSheetEntryProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapStyleSheetEntryProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MapStyleSheetEntryProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapStyleSheetEntryStateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapStyleSheetEntryStateProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MapStyleSheetEntryStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TagProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TagProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TagProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementStatics4> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementStatics4>
{
    int32_t WINRT_CALL get_IsEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayer> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayer>
{
    int32_t WINRT_CALL get_MapElements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElements, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement>>(this->shim().MapElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MapElements(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElements, WINRT_WRAP(void), Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement> const&);
            this->shim().MapElements(*reinterpret_cast<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_MapElementClick(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElementClick, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerClickEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapElementClick(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerClickEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapElementClick(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapElementClick, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapElementClick(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MapElementPointerEntered(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElementPointerEntered, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerEnteredEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapElementPointerEntered(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerEnteredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapElementPointerEntered(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapElementPointerEntered, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapElementPointerEntered(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MapElementPointerExited(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElementPointerExited, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerExitedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapElementPointerExited(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerExitedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapElementPointerExited(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapElementPointerExited, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapElementPointerExited(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_MapContextRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapContextRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerContextRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().MapContextRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapElementsLayer, Windows::UI::Xaml::Controls::Maps::MapElementsLayerContextRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_MapContextRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(MapContextRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().MapContextRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayerClickEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayerClickEventArgs>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapElements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElements, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::Controls::Maps::MapElement>>(this->shim().MapElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayerContextRequestedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayerContextRequestedEventArgs>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapElements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElements, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Controls::Maps::MapElement>>(this->shim().MapElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerEnteredEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerEnteredEventArgs>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElement, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapElement));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapElement>(this->shim().MapElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerExitedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerExitedEventArgs>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MapElement(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElement, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapElement));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapElement>(this->shim().MapElement());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayerStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapElementsLayerStatics>
{
    int32_t WINRT_CALL get_MapElementsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapElementsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MapElementsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapIcon> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapIcon>
{
    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Location(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(void), Windows::Devices::Geolocation::Geopoint const&);
            this->shim().Location(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Title(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Title(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Title, WINRT_WRAP(void), hstring const&);
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalizedAnchorPoint(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedAnchorPoint, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().NormalizedAnchorPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_NormalizedAnchorPoint(Windows::Foundation::Point value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedAnchorPoint, WINRT_WRAP(void), Windows::Foundation::Point const&);
            this->shim().NormalizedAnchorPoint(*reinterpret_cast<Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Image(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Image, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Image());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Image(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Image, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().Image(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapIcon2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapIcon2>
{
    int32_t WINRT_CALL get_CollisionBehaviorDesired(Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CollisionBehaviorDesired, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior>(this->shim().CollisionBehaviorDesired());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CollisionBehaviorDesired(Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CollisionBehaviorDesired, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior const&);
            this->shim().CollisionBehaviorDesired(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapElementCollisionBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapIconStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapIconStatics>
{
    int32_t WINRT_CALL get_LocationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LocationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LocationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TitleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TitleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TitleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NormalizedAnchorPointProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NormalizedAnchorPointProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().NormalizedAnchorPointProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapIconStatics2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapIconStatics2>
{
    int32_t WINRT_CALL get_CollisionBehaviorDesiredProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CollisionBehaviorDesiredProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().CollisionBehaviorDesiredProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapInputEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapInputEventArgs>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapItemsControl> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapItemsControl>
{
    int32_t WINRT_CALL get_ItemsSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsSource, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().ItemsSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ItemsSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsSource, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().ItemsSource(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
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
            WINRT_ASSERT_DECLARATION(Items, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::Xaml::DependencyObject>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemTemplate(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemTemplate, WINRT_WRAP(Windows::UI::Xaml::DataTemplate));
            *value = detach_from<Windows::UI::Xaml::DataTemplate>(this->shim().ItemTemplate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ItemTemplate(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemTemplate, WINRT_WRAP(void), Windows::UI::Xaml::DataTemplate const&);
            this->shim().ItemTemplate(*reinterpret_cast<Windows::UI::Xaml::DataTemplate const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapItemsControlStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapItemsControlStatics>
{
    int32_t WINRT_CALL get_ItemsSourceProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsSourceProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ItemsSourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ItemsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemTemplateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemTemplateProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ItemTemplateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapLayer> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapLayer>
{
    int32_t WINRT_CALL get_MapTabIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapTabIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().MapTabIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MapTabIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapTabIndex, WINRT_WRAP(void), int32_t);
            this->shim().MapTabIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Visible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Visible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(void), bool);
            this->shim().Visible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ZIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ZIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndex, WINRT_WRAP(void), int32_t);
            this->shim().ZIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapLayerFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapLayerFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapLayer), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapLayer>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapLayerStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapLayerStatics>
{
    int32_t WINRT_CALL get_MapTabIndexProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MapTabIndexProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().MapTabIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VisibleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisibleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().VisibleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZIndexProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndexProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ZIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapModel3D> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapModel3D>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapModel3DFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapModel3DFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapModel3D), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapModel3D>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapModel3DStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapModel3DStatics>
{
    int32_t WINRT_CALL CreateFrom3MFAsync(void* source, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFrom3MFAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::MapModel3D>), Windows::Storage::Streams::IRandomAccessStreamReference const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::MapModel3D>>(this->shim().CreateFrom3MFAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&source)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFrom3MFWithShadingOptionAsync(void* source, Windows::UI::Xaml::Controls::Maps::MapModel3DShadingOption shadingOption, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFrom3MFAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::MapModel3D>), Windows::Storage::Streams::IRandomAccessStreamReference const, Windows::UI::Xaml::Controls::Maps::MapModel3DShadingOption const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::MapModel3D>>(this->shim().CreateFrom3MFAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&source), *reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapModel3DShadingOption const*>(&shadingOption)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapPolygon> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapPolygon>
{
    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(Windows::Devices::Geolocation::Geopath));
            *value = detach_from<Windows::Devices::Geolocation::Geopath>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Path(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(void), Windows::Devices::Geolocation::Geopath const&);
            this->shim().Path(*reinterpret_cast<Windows::Devices::Geolocation::Geopath const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().StrokeColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().StrokeColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeThickness(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeThickness, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().StrokeThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeThickness(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeThickness, WINRT_WRAP(void), double);
            this->shim().StrokeThickness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().StrokeDashed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeDashed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashed, WINRT_WRAP(void), bool);
            this->shim().StrokeDashed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FillColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().FillColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FillColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FillColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().FillColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapPolygon2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapPolygon2>
{
    int32_t WINRT_CALL get_Paths(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Paths, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Devices::Geolocation::Geopath>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Devices::Geolocation::Geopath>>(this->shim().Paths());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapPolygonStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapPolygonStatics>
{
    int32_t WINRT_CALL get_PathProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PathProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PathProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeThicknessProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeThicknessProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeThicknessProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashedProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeDashedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapPolyline> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapPolyline>
{
    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(Windows::Devices::Geolocation::Geopath));
            *value = detach_from<Windows::Devices::Geolocation::Geopath>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Path(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(void), Windows::Devices::Geolocation::Geopath const&);
            this->shim().Path(*reinterpret_cast<Windows::Devices::Geolocation::Geopath const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().StrokeColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().StrokeColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeThickness(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeThickness, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().StrokeThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeThickness(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeThickness, WINRT_WRAP(void), double);
            this->shim().StrokeThickness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashed(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashed, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().StrokeDashed());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StrokeDashed(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashed, WINRT_WRAP(void), bool);
            this->shim().StrokeDashed(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapPolylineStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapPolylineStatics>
{
    int32_t WINRT_CALL get_PathProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PathProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().PathProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StrokeDashedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StrokeDashedProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().StrokeDashedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapRightTappedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapRightTappedEventArgs>
{
    int32_t WINRT_CALL get_Position(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Position, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapRouteView> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapRouteView>
{
    int32_t WINRT_CALL get_RouteColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RouteColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().RouteColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RouteColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RouteColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().RouteColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OutlineColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutlineColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().OutlineColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OutlineColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OutlineColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().OutlineColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Route(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Route, WINRT_WRAP(Windows::Services::Maps::MapRoute));
            *value = detach_from<Windows::Services::Maps::MapRoute>(this->shim().Route());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapRouteViewFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapRouteViewFactory>
{
    int32_t WINRT_CALL CreateInstanceWithMapRoute(void* route, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithMapRoute, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapRouteView), Windows::Services::Maps::MapRoute const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapRouteView>(this->shim().CreateInstanceWithMapRoute(*reinterpret_cast<Windows::Services::Maps::MapRoute const*>(&route), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapScene> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapScene>
{
    int32_t WINRT_CALL get_TargetCamera(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetCamera, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCamera));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCamera>(this->shim().TargetCamera());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_TargetCameraChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetCameraChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapScene, Windows::UI::Xaml::Controls::Maps::MapTargetCameraChangedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TargetCameraChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::Xaml::Controls::Maps::MapScene, Windows::UI::Xaml::Controls::Maps::MapTargetCameraChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TargetCameraChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TargetCameraChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TargetCameraChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapSceneStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapSceneStatics>
{
    int32_t WINRT_CALL CreateFromBoundingBox(void* bounds, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBoundingBox, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapScene), Windows::Devices::Geolocation::GeoboundingBox const&);
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapScene>(this->shim().CreateFromBoundingBox(*reinterpret_cast<Windows::Devices::Geolocation::GeoboundingBox const*>(&bounds)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromBoundingBoxWithHeadingAndPitch(void* bounds, double headingInDegrees, double pitchInDegrees, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromBoundingBox, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapScene), Windows::Devices::Geolocation::GeoboundingBox const&, double, double);
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapScene>(this->shim().CreateFromBoundingBox(*reinterpret_cast<Windows::Devices::Geolocation::GeoboundingBox const*>(&bounds), headingInDegrees, pitchInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromCamera(void* camera, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromCamera, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapScene), Windows::UI::Xaml::Controls::Maps::MapCamera const&);
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapScene>(this->shim().CreateFromCamera(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapCamera const*>(&camera)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromLocation(void* location, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromLocation, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapScene), Windows::Devices::Geolocation::Geopoint const&);
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapScene>(this->shim().CreateFromLocation(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromLocationWithHeadingAndPitch(void* location, double headingInDegrees, double pitchInDegrees, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromLocation, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapScene), Windows::Devices::Geolocation::Geopoint const&, double, double);
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapScene>(this->shim().CreateFromLocation(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location), headingInDegrees, pitchInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromLocationAndRadius(void* location, double radiusInMeters, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromLocationAndRadius, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapScene), Windows::Devices::Geolocation::Geopoint const&, double);
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapScene>(this->shim().CreateFromLocationAndRadius(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location), radiusInMeters));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromLocationAndRadiusWithHeadingAndPitch(void* location, double radiusInMeters, double headingInDegrees, double pitchInDegrees, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromLocationAndRadius, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapScene), Windows::Devices::Geolocation::Geopoint const&, double, double, double);
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapScene>(this->shim().CreateFromLocationAndRadius(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location), radiusInMeters, headingInDegrees, pitchInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromLocations(void* locations, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromLocations, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapScene), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const&);
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapScene>(this->shim().CreateFromLocations(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const*>(&locations)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateFromLocationsWithHeadingAndPitch(void* locations, double headingInDegrees, double pitchInDegrees, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateFromLocations, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapScene), Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const&, double, double);
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapScene>(this->shim().CreateFromLocations(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Devices::Geolocation::Geopoint> const*>(&locations), headingInDegrees, pitchInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapStyleSheet> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapStyleSheet>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>
{
    int32_t WINRT_CALL get_Area(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Area, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Area());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Airport(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Airport, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Airport());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Cemetery(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cemetery, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Cemetery());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Continent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Continent, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Continent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Education(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Education, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Education());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IndigenousPeoplesReserve(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndigenousPeoplesReserve, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IndigenousPeoplesReserve());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Island(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Island, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Island());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Medical(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Medical, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Medical());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Military(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Military, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Military());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Nautical(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Nautical, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Nautical());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Neighborhood(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Neighborhood, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Neighborhood());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Runway(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Runway, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Runway());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Sand(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Sand, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Sand());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShoppingCenter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShoppingCenter, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ShoppingCenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Stadium(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Stadium, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Stadium());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Vegetation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Vegetation, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Vegetation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Forest(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Forest, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Forest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GolfCourse(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GolfCourse, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GolfCourse());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Park(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Park, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Park());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PlayingField(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PlayingField, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PlayingField());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Reserve(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Reserve, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Reserve());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Point(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Point, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Point());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NaturalPoint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NaturalPoint, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().NaturalPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Peak(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Peak, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Peak());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VolcanicPeak(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VolcanicPeak, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().VolcanicPeak());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WaterPoint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaterPoint, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WaterPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PointOfInterest(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PointOfInterest, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PointOfInterest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Business(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Business, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Business());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FoodPoint(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FoodPoint, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().FoodPoint());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PopulatedPlace(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PopulatedPlace, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PopulatedPlace());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Capital(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Capital, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Capital());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdminDistrictCapital(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdminDistrictCapital, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AdminDistrictCapital());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CountryRegionCapital(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CountryRegionCapital, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CountryRegionCapital());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoadShield(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoadShield, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RoadShield());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoadExit(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoadExit, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RoadExit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Transit(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transit, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Transit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Political(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Political, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Political());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CountryRegion(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CountryRegion, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().CountryRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AdminDistrict(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AdminDistrict, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().AdminDistrict());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_District(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(District, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().District());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Structure(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Structure, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Structure());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Building(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Building, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Building());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_EducationBuilding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(EducationBuilding, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().EducationBuilding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MedicalBuilding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MedicalBuilding, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MedicalBuilding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TransitBuilding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TransitBuilding, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TransitBuilding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Transportation(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Transportation, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Transportation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Road(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Road, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Road());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ControlledAccessHighway(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ControlledAccessHighway, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ControlledAccessHighway());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HighSpeedRamp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HighSpeedRamp, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().HighSpeedRamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Highway(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Highway, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Highway());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MajorRoad(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MajorRoad, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().MajorRoad());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ArterialRoad(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ArterialRoad, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ArterialRoad());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Street(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Street, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Street());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Ramp(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Ramp, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Ramp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UnpavedStreet(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UnpavedStreet, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UnpavedStreet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TollRoad(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TollRoad, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TollRoad());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Railway(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Railway, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Railway());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Trail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Trail, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Trail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WaterRoute(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WaterRoute, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WaterRoute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Water(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Water, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Water());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_River(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(River, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().River());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RouteLine(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RouteLine, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RouteLine());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WalkingRoute(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WalkingRoute, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().WalkingRoute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DrivingRoute(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DrivingRoute, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DrivingRoute());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntryStatesStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntryStatesStatics>
{
    int32_t WINRT_CALL get_Disabled(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Disabled, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Disabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Hover(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Hover, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Hover());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Selected(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Selected, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Selected());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics>
{
    int32_t WINRT_CALL Aerial(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Aerial, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapStyleSheet));
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapStyleSheet>(this->shim().Aerial());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AerialWithOverlay(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AerialWithOverlay, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapStyleSheet));
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapStyleSheet>(this->shim().AerialWithOverlay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RoadLight(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoadLight, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapStyleSheet));
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapStyleSheet>(this->shim().RoadLight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RoadDark(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoadDark, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapStyleSheet));
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapStyleSheet>(this->shim().RoadDark());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RoadHighContrastLight(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoadHighContrastLight, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapStyleSheet));
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapStyleSheet>(this->shim().RoadHighContrastLight());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RoadHighContrastDark(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoadHighContrastDark, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapStyleSheet));
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapStyleSheet>(this->shim().RoadHighContrastDark());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Combine(void* styleSheets, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Combine, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapStyleSheet), Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Controls::Maps::MapStyleSheet> const&);
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapStyleSheet>(this->shim().Combine(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Xaml::Controls::Maps::MapStyleSheet> const*>(&styleSheets)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ParseFromJson(void* styleAsJson, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParseFromJson, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapStyleSheet), hstring const&);
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapStyleSheet>(this->shim().ParseFromJson(*reinterpret_cast<hstring const*>(&styleAsJson)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryParseFromJson(void* styleAsJson, void** styleSheet, bool* returnValue) noexcept final
    {
        try
        {
            *styleSheet = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryParseFromJson, WINRT_WRAP(bool), hstring const&, Windows::UI::Xaml::Controls::Maps::MapStyleSheet&);
            *returnValue = detach_from<bool>(this->shim().TryParseFromJson(*reinterpret_cast<hstring const*>(&styleAsJson), *reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapStyleSheet*>(styleSheet)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTargetCameraChangedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTargetCameraChangedEventArgs>
{
    int32_t WINRT_CALL get_Camera(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Camera, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCamera));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCamera>(this->shim().Camera());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTargetCameraChangedEventArgs2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTargetCameraChangedEventArgs2>
{
    int32_t WINRT_CALL get_ChangeReason(Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ChangeReason, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapCameraChangeReason>(this->shim().ChangeReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequest> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequest>
{
    int32_t WINRT_CALL get_PixelData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelData, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamReference));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().PixelData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PixelData(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PixelData, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamReference const&);
            this->shim().PixelData(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
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
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestDeferral));
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestDeferral> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs>
{
    int32_t WINRT_CALL get_X(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().X());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Y(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Y, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Y());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomLevel(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomLevel, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ZoomLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequest));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs2>
{
    int32_t WINRT_CALL get_FrameIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FrameIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileDataSource> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileDataSource>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileDataSourceFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileDataSourceFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileDataSource), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileDataSource>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileSource> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileSource>
{
    int32_t WINRT_CALL get_DataSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataSource, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileDataSource));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileDataSource>(this->shim().DataSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DataSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataSource, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapTileDataSource const&);
            this->shim().DataSource(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapTileDataSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Layer(Windows::UI::Xaml::Controls::Maps::MapTileLayer* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Layer, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileLayer));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileLayer>(this->shim().Layer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Layer(Windows::UI::Xaml::Controls::Maps::MapTileLayer value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Layer, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapTileLayer const&);
            this->shim().Layer(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapTileLayer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomLevelRange(struct struct_Windows_UI_Xaml_Controls_Maps_MapZoomLevelRange* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomLevelRange, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange>(this->shim().ZoomLevelRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ZoomLevelRange(struct struct_Windows_UI_Xaml_Controls_Maps_MapZoomLevelRange value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomLevelRange, WINRT_WRAP(void), Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const&);
            this->shim().ZoomLevelRange(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Bounds(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(Windows::Devices::Geolocation::GeoboundingBox));
            *value = detach_from<Windows::Devices::Geolocation::GeoboundingBox>(this->shim().Bounds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Bounds(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bounds, WINRT_WRAP(void), Windows::Devices::Geolocation::GeoboundingBox const&);
            this->shim().Bounds(*reinterpret_cast<Windows::Devices::Geolocation::GeoboundingBox const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowOverstretch(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowOverstretch, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowOverstretch());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowOverstretch(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowOverstretch, WINRT_WRAP(void), bool);
            this->shim().AllowOverstretch(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFadingEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFadingEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsFadingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsFadingEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFadingEnabled, WINRT_WRAP(void), bool);
            this->shim().IsFadingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTransparencyEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTransparencyEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsTransparencyEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsTransparencyEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTransparencyEnabled, WINRT_WRAP(void), bool);
            this->shim().IsTransparencyEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRetryEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRetryEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsRetryEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsRetryEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRetryEnabled, WINRT_WRAP(void), bool);
            this->shim().IsRetryEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ZIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ZIndex(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndex, WINRT_WRAP(void), int32_t);
            this->shim().ZIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TilePixelSize(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TilePixelSize, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().TilePixelSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TilePixelSize(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TilePixelSize, WINRT_WRAP(void), int32_t);
            this->shim().TilePixelSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Visible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Visible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Visible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Visible, WINRT_WRAP(void), bool);
            this->shim().Visible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileSource2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileSource2>
{
    int32_t WINRT_CALL get_AnimationState(Windows::UI::Xaml::Controls::Maps::MapTileAnimationState* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnimationState, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileAnimationState));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileAnimationState>(this->shim().AnimationState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoPlay(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoPlay, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AutoPlay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AutoPlay(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoPlay, WINRT_WRAP(void), bool);
            this->shim().AutoPlay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameCount(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameCount, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FrameCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FrameCount(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameCount, WINRT_WRAP(void), int32_t);
            this->shim().FrameCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameDuration(Windows::Foundation::TimeSpan* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameDuration, WINRT_WRAP(Windows::Foundation::TimeSpan));
            *value = detach_from<Windows::Foundation::TimeSpan>(this->shim().FrameDuration());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FrameDuration(Windows::Foundation::TimeSpan value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameDuration, WINRT_WRAP(void), Windows::Foundation::TimeSpan const&);
            this->shim().FrameDuration(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Pause() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pause, WINRT_WRAP(void));
            this->shim().Pause();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Play() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Play, WINRT_WRAP(void));
            this->shim().Play();
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
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileSource), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileSource>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithDataSource(void* dataSource, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithDataSource, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileSource), Windows::UI::Xaml::Controls::Maps::MapTileDataSource const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileSource>(this->shim().CreateInstanceWithDataSource(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapTileDataSource const*>(&dataSource), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithDataSourceAndZoomRange(void* dataSource, struct struct_Windows_UI_Xaml_Controls_Maps_MapZoomLevelRange zoomLevelRange, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithDataSourceAndZoomRange, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileSource), Windows::UI::Xaml::Controls::Maps::MapTileDataSource const&, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileSource>(this->shim().CreateInstanceWithDataSourceAndZoomRange(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapTileDataSource const*>(&dataSource), *reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const*>(&zoomLevelRange), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithDataSourceZoomRangeAndBounds(void* dataSource, struct struct_Windows_UI_Xaml_Controls_Maps_MapZoomLevelRange zoomLevelRange, void* bounds, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithDataSourceZoomRangeAndBounds, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileSource), Windows::UI::Xaml::Controls::Maps::MapTileDataSource const&, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const&, Windows::Devices::Geolocation::GeoboundingBox const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileSource>(this->shim().CreateInstanceWithDataSourceZoomRangeAndBounds(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapTileDataSource const*>(&dataSource), *reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const*>(&zoomLevelRange), *reinterpret_cast<Windows::Devices::Geolocation::GeoboundingBox const*>(&bounds), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithDataSourceZoomRangeBoundsAndTileSize(void* dataSource, struct struct_Windows_UI_Xaml_Controls_Maps_MapZoomLevelRange zoomLevelRange, void* bounds, int32_t tileSizeInPixels, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstanceWithDataSourceZoomRangeBoundsAndTileSize, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileSource), Windows::UI::Xaml::Controls::Maps::MapTileDataSource const&, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const&, Windows::Devices::Geolocation::GeoboundingBox const&, int32_t, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileSource>(this->shim().CreateInstanceWithDataSourceZoomRangeBoundsAndTileSize(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapTileDataSource const*>(&dataSource), *reinterpret_cast<Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const*>(&zoomLevelRange), *reinterpret_cast<Windows::Devices::Geolocation::GeoboundingBox const*>(&bounds), tileSizeInPixels, *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>
{
    int32_t WINRT_CALL get_DataSourceProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataSourceProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().DataSourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LayerProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LayerProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().LayerProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomLevelRangeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomLevelRangeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ZoomLevelRangeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BoundsProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundsProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().BoundsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowOverstretchProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowOverstretchProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AllowOverstretchProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsFadingEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsFadingEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsFadingEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsTransparencyEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsTransparencyEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsTransparencyEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsRetryEnabledProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsRetryEnabledProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsRetryEnabledProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZIndexProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZIndexProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ZIndexProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TilePixelSizeProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TilePixelSizeProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().TilePixelSizeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VisibleProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisibleProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().VisibleProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2>
{
    int32_t WINRT_CALL get_AnimationStateProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnimationStateProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AnimationStateProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AutoPlayProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AutoPlayProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().AutoPlayProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameCountProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameCountProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FrameCountProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_FrameDurationProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameDurationProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().FrameDurationProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileUriRequest> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileUriRequest>
{
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

    int32_t WINRT_CALL put_Uri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Uri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Uri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
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
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileUriRequestDeferral));
            *result = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileUriRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestDeferral> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestDeferral>
{
    int32_t WINRT_CALL Complete() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Complete, WINRT_WRAP(void));
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs>
{
    int32_t WINRT_CALL get_X(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(X, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().X());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Y(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Y, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Y());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomLevel(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomLevel, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().ZoomLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::MapTileUriRequest));
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::MapTileUriRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs2> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs2>
{
    int32_t WINRT_CALL get_FrameIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FrameIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FrameIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IStreetsideExperience> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IStreetsideExperience>
{
    int32_t WINRT_CALL get_AddressTextVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddressTextVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AddressTextVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AddressTextVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddressTextVisible, WINRT_WRAP(void), bool);
            this->shim().AddressTextVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CursorVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CursorVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CursorVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_CursorVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CursorVisible, WINRT_WRAP(void), bool);
            this->shim().CursorVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_OverviewMapVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverviewMapVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().OverviewMapVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_OverviewMapVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(OverviewMapVisible, WINRT_WRAP(void), bool);
            this->shim().OverviewMapVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StreetLabelsVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreetLabelsVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().StreetLabelsVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_StreetLabelsVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StreetLabelsVisible, WINRT_WRAP(void), bool);
            this->shim().StreetLabelsVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExitButtonVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitButtonVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ExitButtonVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ExitButtonVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExitButtonVisible, WINRT_WRAP(void), bool);
            this->shim().ExitButtonVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ZoomButtonsVisible(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomButtonsVisible, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ZoomButtonsVisible());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ZoomButtonsVisible(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ZoomButtonsVisible, WINRT_WRAP(void), bool);
            this->shim().ZoomButtonsVisible(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IStreetsideExperienceFactory> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IStreetsideExperienceFactory>
{
    int32_t WINRT_CALL CreateInstanceWithPanorama(void* panorama, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithPanorama, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::StreetsideExperience), Windows::UI::Xaml::Controls::Maps::StreetsidePanorama const&);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::StreetsideExperience>(this->shim().CreateInstanceWithPanorama(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama const*>(&panorama)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateInstanceWithPanoramaHeadingPitchAndFieldOfView(void* panorama, double headingInDegrees, double pitchInDegrees, double fieldOfViewInDegrees, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateInstanceWithPanoramaHeadingPitchAndFieldOfView, WINRT_WRAP(Windows::UI::Xaml::Controls::Maps::StreetsideExperience), Windows::UI::Xaml::Controls::Maps::StreetsidePanorama const&, double, double, double);
            *value = detach_from<Windows::UI::Xaml::Controls::Maps::StreetsideExperience>(this->shim().CreateInstanceWithPanoramaHeadingPitchAndFieldOfView(*reinterpret_cast<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama const*>(&panorama), headingInDegrees, pitchInDegrees, fieldOfViewInDegrees));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IStreetsidePanorama> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IStreetsidePanorama>
{
    int32_t WINRT_CALL get_Location(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Location, WINRT_WRAP(Windows::Devices::Geolocation::Geopoint));
            *value = detach_from<Windows::Devices::Geolocation::Geopoint>(this->shim().Location());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Controls::Maps::IStreetsidePanoramaStatics> : produce_base<D, Windows::UI::Xaml::Controls::Maps::IStreetsidePanoramaStatics>
{
    int32_t WINRT_CALL FindNearbyWithLocationAsync(void* location, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindNearbyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama>), Windows::Devices::Geolocation::Geopoint const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama>>(this->shim().FindNearbyAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindNearbyWithLocationAndRadiusAsync(void* location, double radiusInMeters, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindNearbyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama>), Windows::Devices::Geolocation::Geopoint const, double);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama>>(this->shim().FindNearbyAsync(*reinterpret_cast<Windows::Devices::Geolocation::Geopoint const*>(&location), radiusInMeters));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Controls::Maps {

inline CustomMapTileDataSource::CustomMapTileDataSource()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<CustomMapTileDataSource, Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSourceFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline HttpMapTileDataSource::HttpMapTileDataSource()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<HttpMapTileDataSource, Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSourceFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline HttpMapTileDataSource::HttpMapTileDataSource(param::hstring const& uriFormatString)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<HttpMapTileDataSource, Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSourceFactory>([&](auto&& f) { return f.CreateInstanceWithUriFormatString(uriFormatString, baseInterface, innerInterface); });
}

inline LocalMapTileDataSource::LocalMapTileDataSource()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<LocalMapTileDataSource, Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSourceFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline LocalMapTileDataSource::LocalMapTileDataSource(param::hstring const& uriFormatString)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<LocalMapTileDataSource, Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSourceFactory>([&](auto&& f) { return f.CreateInstanceWithUriFormatString(uriFormatString, baseInterface, innerInterface); });
}

inline MapActualCameraChangedEventArgs::MapActualCameraChangedEventArgs() :
    MapActualCameraChangedEventArgs(impl::call_factory<MapActualCameraChangedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapActualCameraChangedEventArgs>(); }))
{}

inline MapActualCameraChangingEventArgs::MapActualCameraChangingEventArgs() :
    MapActualCameraChangingEventArgs(impl::call_factory<MapActualCameraChangingEventArgs>([](auto&& f) { return f.template ActivateInstance<MapActualCameraChangingEventArgs>(); }))
{}

inline MapBillboard::MapBillboard(Windows::UI::Xaml::Controls::Maps::MapCamera const& camera) :
    MapBillboard(impl::call_factory<MapBillboard, Windows::UI::Xaml::Controls::Maps::IMapBillboardFactory>([&](auto&& f) { return f.CreateInstanceFromCamera(camera); }))
{}

inline Windows::UI::Xaml::DependencyProperty MapBillboard::LocationProperty()
{
    return impl::call_factory<MapBillboard, Windows::UI::Xaml::Controls::Maps::IMapBillboardStatics>([&](auto&& f) { return f.LocationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapBillboard::NormalizedAnchorPointProperty()
{
    return impl::call_factory<MapBillboard, Windows::UI::Xaml::Controls::Maps::IMapBillboardStatics>([&](auto&& f) { return f.NormalizedAnchorPointProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapBillboard::CollisionBehaviorDesiredProperty()
{
    return impl::call_factory<MapBillboard, Windows::UI::Xaml::Controls::Maps::IMapBillboardStatics>([&](auto&& f) { return f.CollisionBehaviorDesiredProperty(); });
}

inline MapCamera::MapCamera(Windows::Devices::Geolocation::Geopoint const& location) :
    MapCamera(impl::call_factory<MapCamera, Windows::UI::Xaml::Controls::Maps::IMapCameraFactory>([&](auto&& f) { return f.CreateInstanceWithLocation(location); }))
{}

inline MapCamera::MapCamera(Windows::Devices::Geolocation::Geopoint const& location, double headingInDegrees) :
    MapCamera(impl::call_factory<MapCamera, Windows::UI::Xaml::Controls::Maps::IMapCameraFactory>([&](auto&& f) { return f.CreateInstanceWithLocationAndHeading(location, headingInDegrees); }))
{}

inline MapCamera::MapCamera(Windows::Devices::Geolocation::Geopoint const& location, double headingInDegrees, double pitchInDegrees) :
    MapCamera(impl::call_factory<MapCamera, Windows::UI::Xaml::Controls::Maps::IMapCameraFactory>([&](auto&& f) { return f.CreateInstanceWithLocationHeadingAndPitch(location, headingInDegrees, pitchInDegrees); }))
{}

inline MapCamera::MapCamera(Windows::Devices::Geolocation::Geopoint const& location, double headingInDegrees, double pitchInDegrees, double rollInDegrees, double fieldOfViewInDegrees) :
    MapCamera(impl::call_factory<MapCamera, Windows::UI::Xaml::Controls::Maps::IMapCameraFactory>([&](auto&& f) { return f.CreateInstanceWithLocationHeadingPitchRollAndFieldOfView(location, headingInDegrees, pitchInDegrees, rollInDegrees, fieldOfViewInDegrees); }))
{}

inline MapContextRequestedEventArgs::MapContextRequestedEventArgs() :
    MapContextRequestedEventArgs(impl::call_factory<MapContextRequestedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapContextRequestedEventArgs>(); }))
{}

inline MapControl::MapControl() :
    MapControl(impl::call_factory<MapControl>([](auto&& f) { return f.template ActivateInstance<MapControl>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty MapControl::CenterProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.CenterProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::ChildrenProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.ChildrenProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::ColorSchemeProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.ColorSchemeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::DesiredPitchProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.DesiredPitchProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::HeadingProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.HeadingProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::LandmarksVisibleProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.LandmarksVisibleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::LoadingStatusProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.LoadingStatusProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::MapServiceTokenProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.MapServiceTokenProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::PedestrianFeaturesVisibleProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.PedestrianFeaturesVisibleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::PitchProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.PitchProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::StyleProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.StyleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::TrafficFlowVisibleProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.TrafficFlowVisibleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::TransformOriginProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.TransformOriginProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::WatermarkModeProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.WatermarkModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::ZoomLevelProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.ZoomLevelProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::MapElementsProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.MapElementsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::RoutesProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.RoutesProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::TileSourcesProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.TileSourcesProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::LocationProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.LocationProperty(); });
}

inline Windows::Devices::Geolocation::Geopoint MapControl::GetLocation(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.GetLocation(element); });
}

inline void MapControl::SetLocation(Windows::UI::Xaml::DependencyObject const& element, Windows::Devices::Geolocation::Geopoint const& value)
{
    impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.SetLocation(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::NormalizedAnchorPointProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.NormalizedAnchorPointProperty(); });
}

inline Windows::Foundation::Point MapControl::GetNormalizedAnchorPoint(Windows::UI::Xaml::DependencyObject const& element)
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.GetNormalizedAnchorPoint(element); });
}

inline void MapControl::SetNormalizedAnchorPoint(Windows::UI::Xaml::DependencyObject const& element, Windows::Foundation::Point const& value)
{
    impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics>([&](auto&& f) { return f.SetNormalizedAnchorPoint(element, value); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::BusinessLandmarksVisibleProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics2>([&](auto&& f) { return f.BusinessLandmarksVisibleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::TransitFeaturesVisibleProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics2>([&](auto&& f) { return f.TransitFeaturesVisibleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::PanInteractionModeProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics2>([&](auto&& f) { return f.PanInteractionModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::RotateInteractionModeProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics2>([&](auto&& f) { return f.RotateInteractionModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::TiltInteractionModeProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics2>([&](auto&& f) { return f.TiltInteractionModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::ZoomInteractionModeProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics2>([&](auto&& f) { return f.ZoomInteractionModeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::Is3DSupportedProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics2>([&](auto&& f) { return f.Is3DSupportedProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::IsStreetsideSupportedProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics2>([&](auto&& f) { return f.IsStreetsideSupportedProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::SceneProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics2>([&](auto&& f) { return f.SceneProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::BusinessLandmarksEnabledProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics4>([&](auto&& f) { return f.BusinessLandmarksEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::TransitFeaturesEnabledProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics4>([&](auto&& f) { return f.TransitFeaturesEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::MapProjectionProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics5>([&](auto&& f) { return f.MapProjectionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::StyleSheetProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics5>([&](auto&& f) { return f.StyleSheetProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::ViewPaddingProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics5>([&](auto&& f) { return f.ViewPaddingProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::LayersProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics6>([&](auto&& f) { return f.LayersProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::RegionProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics7>([&](auto&& f) { return f.RegionProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::CanTiltDownProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics8>([&](auto&& f) { return f.CanTiltDownProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::CanTiltUpProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics8>([&](auto&& f) { return f.CanTiltUpProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::CanZoomInProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics8>([&](auto&& f) { return f.CanZoomInProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapControl::CanZoomOutProperty()
{
    return impl::call_factory<MapControl, Windows::UI::Xaml::Controls::Maps::IMapControlStatics8>([&](auto&& f) { return f.CanZoomOutProperty(); });
}

inline MapControlBusinessLandmarkClickEventArgs::MapControlBusinessLandmarkClickEventArgs() :
    MapControlBusinessLandmarkClickEventArgs(impl::call_factory<MapControlBusinessLandmarkClickEventArgs>([](auto&& f) { return f.template ActivateInstance<MapControlBusinessLandmarkClickEventArgs>(); }))
{}

inline MapControlBusinessLandmarkPointerEnteredEventArgs::MapControlBusinessLandmarkPointerEnteredEventArgs() :
    MapControlBusinessLandmarkPointerEnteredEventArgs(impl::call_factory<MapControlBusinessLandmarkPointerEnteredEventArgs>([](auto&& f) { return f.template ActivateInstance<MapControlBusinessLandmarkPointerEnteredEventArgs>(); }))
{}

inline MapControlBusinessLandmarkPointerExitedEventArgs::MapControlBusinessLandmarkPointerExitedEventArgs() :
    MapControlBusinessLandmarkPointerExitedEventArgs(impl::call_factory<MapControlBusinessLandmarkPointerExitedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapControlBusinessLandmarkPointerExitedEventArgs>(); }))
{}

inline MapControlBusinessLandmarkRightTappedEventArgs::MapControlBusinessLandmarkRightTappedEventArgs() :
    MapControlBusinessLandmarkRightTappedEventArgs(impl::call_factory<MapControlBusinessLandmarkRightTappedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapControlBusinessLandmarkRightTappedEventArgs>(); }))
{}

inline MapControlDataHelper::MapControlDataHelper(Windows::UI::Xaml::Controls::Maps::MapControl const& map) :
    MapControlDataHelper(impl::call_factory<MapControlDataHelper, Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperFactory>([&](auto&& f) { return f.CreateInstance(map); }))
{}

inline Windows::UI::Xaml::Controls::Maps::MapControl MapControlDataHelper::CreateMapControl(bool rasterRenderMode)
{
    return impl::call_factory<MapControlDataHelper, Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperStatics>([&](auto&& f) { return f.CreateMapControl(rasterRenderMode); });
}

inline MapControlTransitFeatureClickEventArgs::MapControlTransitFeatureClickEventArgs() :
    MapControlTransitFeatureClickEventArgs(impl::call_factory<MapControlTransitFeatureClickEventArgs>([](auto&& f) { return f.template ActivateInstance<MapControlTransitFeatureClickEventArgs>(); }))
{}

inline MapControlTransitFeaturePointerEnteredEventArgs::MapControlTransitFeaturePointerEnteredEventArgs() :
    MapControlTransitFeaturePointerEnteredEventArgs(impl::call_factory<MapControlTransitFeaturePointerEnteredEventArgs>([](auto&& f) { return f.template ActivateInstance<MapControlTransitFeaturePointerEnteredEventArgs>(); }))
{}

inline MapControlTransitFeaturePointerExitedEventArgs::MapControlTransitFeaturePointerExitedEventArgs() :
    MapControlTransitFeaturePointerExitedEventArgs(impl::call_factory<MapControlTransitFeaturePointerExitedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapControlTransitFeaturePointerExitedEventArgs>(); }))
{}

inline MapControlTransitFeatureRightTappedEventArgs::MapControlTransitFeatureRightTappedEventArgs() :
    MapControlTransitFeatureRightTappedEventArgs(impl::call_factory<MapControlTransitFeatureRightTappedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapControlTransitFeatureRightTappedEventArgs>(); }))
{}

inline MapCustomExperience::MapCustomExperience()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MapCustomExperience, Windows::UI::Xaml::Controls::Maps::IMapCustomExperienceFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline MapCustomExperienceChangedEventArgs::MapCustomExperienceChangedEventArgs() :
    MapCustomExperienceChangedEventArgs(impl::call_factory<MapCustomExperienceChangedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapCustomExperienceChangedEventArgs>(); }))
{}

inline MapElement::MapElement()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MapElement, Windows::UI::Xaml::Controls::Maps::IMapElementFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty MapElement::ZIndexProperty()
{
    return impl::call_factory<MapElement, Windows::UI::Xaml::Controls::Maps::IMapElementStatics>([&](auto&& f) { return f.ZIndexProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapElement::VisibleProperty()
{
    return impl::call_factory<MapElement, Windows::UI::Xaml::Controls::Maps::IMapElementStatics>([&](auto&& f) { return f.VisibleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapElement::MapTabIndexProperty()
{
    return impl::call_factory<MapElement, Windows::UI::Xaml::Controls::Maps::IMapElementStatics2>([&](auto&& f) { return f.MapTabIndexProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapElement::MapStyleSheetEntryProperty()
{
    return impl::call_factory<MapElement, Windows::UI::Xaml::Controls::Maps::IMapElementStatics3>([&](auto&& f) { return f.MapStyleSheetEntryProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapElement::MapStyleSheetEntryStateProperty()
{
    return impl::call_factory<MapElement, Windows::UI::Xaml::Controls::Maps::IMapElementStatics3>([&](auto&& f) { return f.MapStyleSheetEntryStateProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapElement::TagProperty()
{
    return impl::call_factory<MapElement, Windows::UI::Xaml::Controls::Maps::IMapElementStatics3>([&](auto&& f) { return f.TagProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapElement::IsEnabledProperty()
{
    return impl::call_factory<MapElement, Windows::UI::Xaml::Controls::Maps::IMapElementStatics4>([&](auto&& f) { return f.IsEnabledProperty(); });
}

inline MapElement3D::MapElement3D() :
    MapElement3D(impl::call_factory<MapElement3D>([](auto&& f) { return f.template ActivateInstance<MapElement3D>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty MapElement3D::LocationProperty()
{
    return impl::call_factory<MapElement3D, Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics>([&](auto&& f) { return f.LocationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapElement3D::HeadingProperty()
{
    return impl::call_factory<MapElement3D, Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics>([&](auto&& f) { return f.HeadingProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapElement3D::PitchProperty()
{
    return impl::call_factory<MapElement3D, Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics>([&](auto&& f) { return f.PitchProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapElement3D::RollProperty()
{
    return impl::call_factory<MapElement3D, Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics>([&](auto&& f) { return f.RollProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapElement3D::ScaleProperty()
{
    return impl::call_factory<MapElement3D, Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics>([&](auto&& f) { return f.ScaleProperty(); });
}

inline MapElementClickEventArgs::MapElementClickEventArgs() :
    MapElementClickEventArgs(impl::call_factory<MapElementClickEventArgs>([](auto&& f) { return f.template ActivateInstance<MapElementClickEventArgs>(); }))
{}

inline MapElementPointerEnteredEventArgs::MapElementPointerEnteredEventArgs() :
    MapElementPointerEnteredEventArgs(impl::call_factory<MapElementPointerEnteredEventArgs>([](auto&& f) { return f.template ActivateInstance<MapElementPointerEnteredEventArgs>(); }))
{}

inline MapElementPointerExitedEventArgs::MapElementPointerExitedEventArgs() :
    MapElementPointerExitedEventArgs(impl::call_factory<MapElementPointerExitedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapElementPointerExitedEventArgs>(); }))
{}

inline MapElementsLayer::MapElementsLayer() :
    MapElementsLayer(impl::call_factory<MapElementsLayer>([](auto&& f) { return f.template ActivateInstance<MapElementsLayer>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty MapElementsLayer::MapElementsProperty()
{
    return impl::call_factory<MapElementsLayer, Windows::UI::Xaml::Controls::Maps::IMapElementsLayerStatics>([&](auto&& f) { return f.MapElementsProperty(); });
}

inline MapElementsLayerClickEventArgs::MapElementsLayerClickEventArgs() :
    MapElementsLayerClickEventArgs(impl::call_factory<MapElementsLayerClickEventArgs>([](auto&& f) { return f.template ActivateInstance<MapElementsLayerClickEventArgs>(); }))
{}

inline MapElementsLayerContextRequestedEventArgs::MapElementsLayerContextRequestedEventArgs() :
    MapElementsLayerContextRequestedEventArgs(impl::call_factory<MapElementsLayerContextRequestedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapElementsLayerContextRequestedEventArgs>(); }))
{}

inline MapElementsLayerPointerEnteredEventArgs::MapElementsLayerPointerEnteredEventArgs() :
    MapElementsLayerPointerEnteredEventArgs(impl::call_factory<MapElementsLayerPointerEnteredEventArgs>([](auto&& f) { return f.template ActivateInstance<MapElementsLayerPointerEnteredEventArgs>(); }))
{}

inline MapElementsLayerPointerExitedEventArgs::MapElementsLayerPointerExitedEventArgs() :
    MapElementsLayerPointerExitedEventArgs(impl::call_factory<MapElementsLayerPointerExitedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapElementsLayerPointerExitedEventArgs>(); }))
{}

inline MapIcon::MapIcon() :
    MapIcon(impl::call_factory<MapIcon>([](auto&& f) { return f.template ActivateInstance<MapIcon>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty MapIcon::LocationProperty()
{
    return impl::call_factory<MapIcon, Windows::UI::Xaml::Controls::Maps::IMapIconStatics>([&](auto&& f) { return f.LocationProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapIcon::TitleProperty()
{
    return impl::call_factory<MapIcon, Windows::UI::Xaml::Controls::Maps::IMapIconStatics>([&](auto&& f) { return f.TitleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapIcon::NormalizedAnchorPointProperty()
{
    return impl::call_factory<MapIcon, Windows::UI::Xaml::Controls::Maps::IMapIconStatics>([&](auto&& f) { return f.NormalizedAnchorPointProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapIcon::CollisionBehaviorDesiredProperty()
{
    return impl::call_factory<MapIcon, Windows::UI::Xaml::Controls::Maps::IMapIconStatics2>([&](auto&& f) { return f.CollisionBehaviorDesiredProperty(); });
}

inline MapInputEventArgs::MapInputEventArgs() :
    MapInputEventArgs(impl::call_factory<MapInputEventArgs>([](auto&& f) { return f.template ActivateInstance<MapInputEventArgs>(); }))
{}

inline MapItemsControl::MapItemsControl() :
    MapItemsControl(impl::call_factory<MapItemsControl>([](auto&& f) { return f.template ActivateInstance<MapItemsControl>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty MapItemsControl::ItemsSourceProperty()
{
    return impl::call_factory<MapItemsControl, Windows::UI::Xaml::Controls::Maps::IMapItemsControlStatics>([&](auto&& f) { return f.ItemsSourceProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapItemsControl::ItemsProperty()
{
    return impl::call_factory<MapItemsControl, Windows::UI::Xaml::Controls::Maps::IMapItemsControlStatics>([&](auto&& f) { return f.ItemsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapItemsControl::ItemTemplateProperty()
{
    return impl::call_factory<MapItemsControl, Windows::UI::Xaml::Controls::Maps::IMapItemsControlStatics>([&](auto&& f) { return f.ItemTemplateProperty(); });
}

inline MapLayer::MapLayer()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MapLayer, Windows::UI::Xaml::Controls::Maps::IMapLayerFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty MapLayer::MapTabIndexProperty()
{
    return impl::call_factory<MapLayer, Windows::UI::Xaml::Controls::Maps::IMapLayerStatics>([&](auto&& f) { return f.MapTabIndexProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapLayer::VisibleProperty()
{
    return impl::call_factory<MapLayer, Windows::UI::Xaml::Controls::Maps::IMapLayerStatics>([&](auto&& f) { return f.VisibleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapLayer::ZIndexProperty()
{
    return impl::call_factory<MapLayer, Windows::UI::Xaml::Controls::Maps::IMapLayerStatics>([&](auto&& f) { return f.ZIndexProperty(); });
}

inline MapModel3D::MapModel3D()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MapModel3D, Windows::UI::Xaml::Controls::Maps::IMapModel3DFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::MapModel3D> MapModel3D::CreateFrom3MFAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& source)
{
    return impl::call_factory<MapModel3D, Windows::UI::Xaml::Controls::Maps::IMapModel3DStatics>([&](auto&& f) { return f.CreateFrom3MFAsync(source); });
}

inline Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::MapModel3D> MapModel3D::CreateFrom3MFAsync(Windows::Storage::Streams::IRandomAccessStreamReference const& source, Windows::UI::Xaml::Controls::Maps::MapModel3DShadingOption const& shadingOption)
{
    return impl::call_factory<MapModel3D, Windows::UI::Xaml::Controls::Maps::IMapModel3DStatics>([&](auto&& f) { return f.CreateFrom3MFAsync(source, shadingOption); });
}

inline MapPolygon::MapPolygon() :
    MapPolygon(impl::call_factory<MapPolygon>([](auto&& f) { return f.template ActivateInstance<MapPolygon>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty MapPolygon::PathProperty()
{
    return impl::call_factory<MapPolygon, Windows::UI::Xaml::Controls::Maps::IMapPolygonStatics>([&](auto&& f) { return f.PathProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapPolygon::StrokeThicknessProperty()
{
    return impl::call_factory<MapPolygon, Windows::UI::Xaml::Controls::Maps::IMapPolygonStatics>([&](auto&& f) { return f.StrokeThicknessProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapPolygon::StrokeDashedProperty()
{
    return impl::call_factory<MapPolygon, Windows::UI::Xaml::Controls::Maps::IMapPolygonStatics>([&](auto&& f) { return f.StrokeDashedProperty(); });
}

inline MapPolyline::MapPolyline() :
    MapPolyline(impl::call_factory<MapPolyline>([](auto&& f) { return f.template ActivateInstance<MapPolyline>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty MapPolyline::PathProperty()
{
    return impl::call_factory<MapPolyline, Windows::UI::Xaml::Controls::Maps::IMapPolylineStatics>([&](auto&& f) { return f.PathProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapPolyline::StrokeDashedProperty()
{
    return impl::call_factory<MapPolyline, Windows::UI::Xaml::Controls::Maps::IMapPolylineStatics>([&](auto&& f) { return f.StrokeDashedProperty(); });
}

inline MapRightTappedEventArgs::MapRightTappedEventArgs() :
    MapRightTappedEventArgs(impl::call_factory<MapRightTappedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapRightTappedEventArgs>(); }))
{}

inline MapRouteView::MapRouteView(Windows::Services::Maps::MapRoute const& route)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MapRouteView, Windows::UI::Xaml::Controls::Maps::IMapRouteViewFactory>([&](auto&& f) { return f.CreateInstanceWithMapRoute(route, baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::Controls::Maps::MapScene MapScene::CreateFromBoundingBox(Windows::Devices::Geolocation::GeoboundingBox const& bounds)
{
    return impl::call_factory<MapScene, Windows::UI::Xaml::Controls::Maps::IMapSceneStatics>([&](auto&& f) { return f.CreateFromBoundingBox(bounds); });
}

inline Windows::UI::Xaml::Controls::Maps::MapScene MapScene::CreateFromBoundingBox(Windows::Devices::Geolocation::GeoboundingBox const& bounds, double headingInDegrees, double pitchInDegrees)
{
    return impl::call_factory<MapScene, Windows::UI::Xaml::Controls::Maps::IMapSceneStatics>([&](auto&& f) { return f.CreateFromBoundingBox(bounds, headingInDegrees, pitchInDegrees); });
}

inline Windows::UI::Xaml::Controls::Maps::MapScene MapScene::CreateFromCamera(Windows::UI::Xaml::Controls::Maps::MapCamera const& camera)
{
    return impl::call_factory<MapScene, Windows::UI::Xaml::Controls::Maps::IMapSceneStatics>([&](auto&& f) { return f.CreateFromCamera(camera); });
}

inline Windows::UI::Xaml::Controls::Maps::MapScene MapScene::CreateFromLocation(Windows::Devices::Geolocation::Geopoint const& location)
{
    return impl::call_factory<MapScene, Windows::UI::Xaml::Controls::Maps::IMapSceneStatics>([&](auto&& f) { return f.CreateFromLocation(location); });
}

inline Windows::UI::Xaml::Controls::Maps::MapScene MapScene::CreateFromLocation(Windows::Devices::Geolocation::Geopoint const& location, double headingInDegrees, double pitchInDegrees)
{
    return impl::call_factory<MapScene, Windows::UI::Xaml::Controls::Maps::IMapSceneStatics>([&](auto&& f) { return f.CreateFromLocation(location, headingInDegrees, pitchInDegrees); });
}

inline Windows::UI::Xaml::Controls::Maps::MapScene MapScene::CreateFromLocationAndRadius(Windows::Devices::Geolocation::Geopoint const& location, double radiusInMeters)
{
    return impl::call_factory<MapScene, Windows::UI::Xaml::Controls::Maps::IMapSceneStatics>([&](auto&& f) { return f.CreateFromLocationAndRadius(location, radiusInMeters); });
}

inline Windows::UI::Xaml::Controls::Maps::MapScene MapScene::CreateFromLocationAndRadius(Windows::Devices::Geolocation::Geopoint const& location, double radiusInMeters, double headingInDegrees, double pitchInDegrees)
{
    return impl::call_factory<MapScene, Windows::UI::Xaml::Controls::Maps::IMapSceneStatics>([&](auto&& f) { return f.CreateFromLocationAndRadius(location, radiusInMeters, headingInDegrees, pitchInDegrees); });
}

inline Windows::UI::Xaml::Controls::Maps::MapScene MapScene::CreateFromLocations(param::iterable<Windows::Devices::Geolocation::Geopoint> const& locations)
{
    return impl::call_factory<MapScene, Windows::UI::Xaml::Controls::Maps::IMapSceneStatics>([&](auto&& f) { return f.CreateFromLocations(locations); });
}

inline Windows::UI::Xaml::Controls::Maps::MapScene MapScene::CreateFromLocations(param::iterable<Windows::Devices::Geolocation::Geopoint> const& locations, double headingInDegrees, double pitchInDegrees)
{
    return impl::call_factory<MapScene, Windows::UI::Xaml::Controls::Maps::IMapSceneStatics>([&](auto&& f) { return f.CreateFromLocations(locations, headingInDegrees, pitchInDegrees); });
}

inline Windows::UI::Xaml::Controls::Maps::MapStyleSheet MapStyleSheet::Aerial()
{
    return impl::call_factory<MapStyleSheet, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics>([&](auto&& f) { return f.Aerial(); });
}

inline Windows::UI::Xaml::Controls::Maps::MapStyleSheet MapStyleSheet::AerialWithOverlay()
{
    return impl::call_factory<MapStyleSheet, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics>([&](auto&& f) { return f.AerialWithOverlay(); });
}

inline Windows::UI::Xaml::Controls::Maps::MapStyleSheet MapStyleSheet::RoadLight()
{
    return impl::call_factory<MapStyleSheet, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics>([&](auto&& f) { return f.RoadLight(); });
}

inline Windows::UI::Xaml::Controls::Maps::MapStyleSheet MapStyleSheet::RoadDark()
{
    return impl::call_factory<MapStyleSheet, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics>([&](auto&& f) { return f.RoadDark(); });
}

inline Windows::UI::Xaml::Controls::Maps::MapStyleSheet MapStyleSheet::RoadHighContrastLight()
{
    return impl::call_factory<MapStyleSheet, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics>([&](auto&& f) { return f.RoadHighContrastLight(); });
}

inline Windows::UI::Xaml::Controls::Maps::MapStyleSheet MapStyleSheet::RoadHighContrastDark()
{
    return impl::call_factory<MapStyleSheet, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics>([&](auto&& f) { return f.RoadHighContrastDark(); });
}

inline Windows::UI::Xaml::Controls::Maps::MapStyleSheet MapStyleSheet::Combine(param::iterable<Windows::UI::Xaml::Controls::Maps::MapStyleSheet> const& styleSheets)
{
    return impl::call_factory<MapStyleSheet, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics>([&](auto&& f) { return f.Combine(styleSheets); });
}

inline Windows::UI::Xaml::Controls::Maps::MapStyleSheet MapStyleSheet::ParseFromJson(param::hstring const& styleAsJson)
{
    return impl::call_factory<MapStyleSheet, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics>([&](auto&& f) { return f.ParseFromJson(styleAsJson); });
}

inline bool MapStyleSheet::TryParseFromJson(param::hstring const& styleAsJson, Windows::UI::Xaml::Controls::Maps::MapStyleSheet& styleSheet)
{
    return impl::call_factory<MapStyleSheet, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics>([&](auto&& f) { return f.TryParseFromJson(styleAsJson, styleSheet); });
}

inline hstring MapStyleSheetEntries::Area()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Area(); });
}

inline hstring MapStyleSheetEntries::Airport()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Airport(); });
}

inline hstring MapStyleSheetEntries::Cemetery()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Cemetery(); });
}

inline hstring MapStyleSheetEntries::Continent()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Continent(); });
}

inline hstring MapStyleSheetEntries::Education()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Education(); });
}

inline hstring MapStyleSheetEntries::IndigenousPeoplesReserve()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.IndigenousPeoplesReserve(); });
}

inline hstring MapStyleSheetEntries::Island()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Island(); });
}

inline hstring MapStyleSheetEntries::Medical()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Medical(); });
}

inline hstring MapStyleSheetEntries::Military()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Military(); });
}

inline hstring MapStyleSheetEntries::Nautical()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Nautical(); });
}

inline hstring MapStyleSheetEntries::Neighborhood()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Neighborhood(); });
}

inline hstring MapStyleSheetEntries::Runway()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Runway(); });
}

inline hstring MapStyleSheetEntries::Sand()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Sand(); });
}

inline hstring MapStyleSheetEntries::ShoppingCenter()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.ShoppingCenter(); });
}

inline hstring MapStyleSheetEntries::Stadium()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Stadium(); });
}

inline hstring MapStyleSheetEntries::Vegetation()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Vegetation(); });
}

inline hstring MapStyleSheetEntries::Forest()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Forest(); });
}

inline hstring MapStyleSheetEntries::GolfCourse()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.GolfCourse(); });
}

inline hstring MapStyleSheetEntries::Park()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Park(); });
}

inline hstring MapStyleSheetEntries::PlayingField()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.PlayingField(); });
}

inline hstring MapStyleSheetEntries::Reserve()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Reserve(); });
}

inline hstring MapStyleSheetEntries::Point()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Point(); });
}

inline hstring MapStyleSheetEntries::NaturalPoint()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.NaturalPoint(); });
}

inline hstring MapStyleSheetEntries::Peak()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Peak(); });
}

inline hstring MapStyleSheetEntries::VolcanicPeak()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.VolcanicPeak(); });
}

inline hstring MapStyleSheetEntries::WaterPoint()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.WaterPoint(); });
}

inline hstring MapStyleSheetEntries::PointOfInterest()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.PointOfInterest(); });
}

inline hstring MapStyleSheetEntries::Business()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Business(); });
}

inline hstring MapStyleSheetEntries::FoodPoint()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.FoodPoint(); });
}

inline hstring MapStyleSheetEntries::PopulatedPlace()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.PopulatedPlace(); });
}

inline hstring MapStyleSheetEntries::Capital()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Capital(); });
}

inline hstring MapStyleSheetEntries::AdminDistrictCapital()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.AdminDistrictCapital(); });
}

inline hstring MapStyleSheetEntries::CountryRegionCapital()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.CountryRegionCapital(); });
}

inline hstring MapStyleSheetEntries::RoadShield()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.RoadShield(); });
}

inline hstring MapStyleSheetEntries::RoadExit()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.RoadExit(); });
}

inline hstring MapStyleSheetEntries::Transit()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Transit(); });
}

inline hstring MapStyleSheetEntries::Political()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Political(); });
}

inline hstring MapStyleSheetEntries::CountryRegion()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.CountryRegion(); });
}

inline hstring MapStyleSheetEntries::AdminDistrict()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.AdminDistrict(); });
}

inline hstring MapStyleSheetEntries::District()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.District(); });
}

inline hstring MapStyleSheetEntries::Structure()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Structure(); });
}

inline hstring MapStyleSheetEntries::Building()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Building(); });
}

inline hstring MapStyleSheetEntries::EducationBuilding()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.EducationBuilding(); });
}

inline hstring MapStyleSheetEntries::MedicalBuilding()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.MedicalBuilding(); });
}

inline hstring MapStyleSheetEntries::TransitBuilding()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.TransitBuilding(); });
}

inline hstring MapStyleSheetEntries::Transportation()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Transportation(); });
}

inline hstring MapStyleSheetEntries::Road()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Road(); });
}

inline hstring MapStyleSheetEntries::ControlledAccessHighway()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.ControlledAccessHighway(); });
}

inline hstring MapStyleSheetEntries::HighSpeedRamp()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.HighSpeedRamp(); });
}

inline hstring MapStyleSheetEntries::Highway()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Highway(); });
}

inline hstring MapStyleSheetEntries::MajorRoad()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.MajorRoad(); });
}

inline hstring MapStyleSheetEntries::ArterialRoad()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.ArterialRoad(); });
}

inline hstring MapStyleSheetEntries::Street()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Street(); });
}

inline hstring MapStyleSheetEntries::Ramp()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Ramp(); });
}

inline hstring MapStyleSheetEntries::UnpavedStreet()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.UnpavedStreet(); });
}

inline hstring MapStyleSheetEntries::TollRoad()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.TollRoad(); });
}

inline hstring MapStyleSheetEntries::Railway()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Railway(); });
}

inline hstring MapStyleSheetEntries::Trail()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Trail(); });
}

inline hstring MapStyleSheetEntries::WaterRoute()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.WaterRoute(); });
}

inline hstring MapStyleSheetEntries::Water()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.Water(); });
}

inline hstring MapStyleSheetEntries::River()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.River(); });
}

inline hstring MapStyleSheetEntries::RouteLine()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.RouteLine(); });
}

inline hstring MapStyleSheetEntries::WalkingRoute()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.WalkingRoute(); });
}

inline hstring MapStyleSheetEntries::DrivingRoute()
{
    return impl::call_factory<MapStyleSheetEntries, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics>([&](auto&& f) { return f.DrivingRoute(); });
}

inline hstring MapStyleSheetEntryStates::Disabled()
{
    return impl::call_factory<MapStyleSheetEntryStates, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntryStatesStatics>([&](auto&& f) { return f.Disabled(); });
}

inline hstring MapStyleSheetEntryStates::Hover()
{
    return impl::call_factory<MapStyleSheetEntryStates, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntryStatesStatics>([&](auto&& f) { return f.Hover(); });
}

inline hstring MapStyleSheetEntryStates::Selected()
{
    return impl::call_factory<MapStyleSheetEntryStates, Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntryStatesStatics>([&](auto&& f) { return f.Selected(); });
}

inline MapTargetCameraChangedEventArgs::MapTargetCameraChangedEventArgs() :
    MapTargetCameraChangedEventArgs(impl::call_factory<MapTargetCameraChangedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapTargetCameraChangedEventArgs>(); }))
{}

inline MapTileBitmapRequest::MapTileBitmapRequest() :
    MapTileBitmapRequest(impl::call_factory<MapTileBitmapRequest>([](auto&& f) { return f.template ActivateInstance<MapTileBitmapRequest>(); }))
{}

inline MapTileBitmapRequestDeferral::MapTileBitmapRequestDeferral() :
    MapTileBitmapRequestDeferral(impl::call_factory<MapTileBitmapRequestDeferral>([](auto&& f) { return f.template ActivateInstance<MapTileBitmapRequestDeferral>(); }))
{}

inline MapTileBitmapRequestedEventArgs::MapTileBitmapRequestedEventArgs() :
    MapTileBitmapRequestedEventArgs(impl::call_factory<MapTileBitmapRequestedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapTileBitmapRequestedEventArgs>(); }))
{}

inline MapTileDataSource::MapTileDataSource()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MapTileDataSource, Windows::UI::Xaml::Controls::Maps::IMapTileDataSourceFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline MapTileSource::MapTileSource()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline MapTileSource::MapTileSource(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory>([&](auto&& f) { return f.CreateInstanceWithDataSource(dataSource, baseInterface, innerInterface); });
}

inline MapTileSource::MapTileSource(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const& zoomLevelRange)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory>([&](auto&& f) { return f.CreateInstanceWithDataSourceAndZoomRange(dataSource, zoomLevelRange, baseInterface, innerInterface); });
}

inline MapTileSource::MapTileSource(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const& zoomLevelRange, Windows::Devices::Geolocation::GeoboundingBox const& bounds)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory>([&](auto&& f) { return f.CreateInstanceWithDataSourceZoomRangeAndBounds(dataSource, zoomLevelRange, bounds, baseInterface, innerInterface); });
}

inline MapTileSource::MapTileSource(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const& zoomLevelRange, Windows::Devices::Geolocation::GeoboundingBox const& bounds, int32_t tileSizeInPixels)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory>([&](auto&& f) { return f.CreateInstanceWithDataSourceZoomRangeBoundsAndTileSize(dataSource, zoomLevelRange, bounds, tileSizeInPixels, baseInterface, innerInterface); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::DataSourceProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>([&](auto&& f) { return f.DataSourceProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::LayerProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>([&](auto&& f) { return f.LayerProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::ZoomLevelRangeProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>([&](auto&& f) { return f.ZoomLevelRangeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::BoundsProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>([&](auto&& f) { return f.BoundsProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::AllowOverstretchProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>([&](auto&& f) { return f.AllowOverstretchProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::IsFadingEnabledProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>([&](auto&& f) { return f.IsFadingEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::IsTransparencyEnabledProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>([&](auto&& f) { return f.IsTransparencyEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::IsRetryEnabledProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>([&](auto&& f) { return f.IsRetryEnabledProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::ZIndexProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>([&](auto&& f) { return f.ZIndexProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::TilePixelSizeProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>([&](auto&& f) { return f.TilePixelSizeProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::VisibleProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics>([&](auto&& f) { return f.VisibleProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::AnimationStateProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2>([&](auto&& f) { return f.AnimationStateProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::AutoPlayProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2>([&](auto&& f) { return f.AutoPlayProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::FrameCountProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2>([&](auto&& f) { return f.FrameCountProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty MapTileSource::FrameDurationProperty()
{
    return impl::call_factory<MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2>([&](auto&& f) { return f.FrameDurationProperty(); });
}

inline MapTileUriRequest::MapTileUriRequest() :
    MapTileUriRequest(impl::call_factory<MapTileUriRequest>([](auto&& f) { return f.template ActivateInstance<MapTileUriRequest>(); }))
{}

inline MapTileUriRequestDeferral::MapTileUriRequestDeferral() :
    MapTileUriRequestDeferral(impl::call_factory<MapTileUriRequestDeferral>([](auto&& f) { return f.template ActivateInstance<MapTileUriRequestDeferral>(); }))
{}

inline MapTileUriRequestedEventArgs::MapTileUriRequestedEventArgs() :
    MapTileUriRequestedEventArgs(impl::call_factory<MapTileUriRequestedEventArgs>([](auto&& f) { return f.template ActivateInstance<MapTileUriRequestedEventArgs>(); }))
{}

inline StreetsideExperience::StreetsideExperience(Windows::UI::Xaml::Controls::Maps::StreetsidePanorama const& panorama) :
    StreetsideExperience(impl::call_factory<StreetsideExperience, Windows::UI::Xaml::Controls::Maps::IStreetsideExperienceFactory>([&](auto&& f) { return f.CreateInstanceWithPanorama(panorama); }))
{}

inline StreetsideExperience::StreetsideExperience(Windows::UI::Xaml::Controls::Maps::StreetsidePanorama const& panorama, double headingInDegrees, double pitchInDegrees, double fieldOfViewInDegrees) :
    StreetsideExperience(impl::call_factory<StreetsideExperience, Windows::UI::Xaml::Controls::Maps::IStreetsideExperienceFactory>([&](auto&& f) { return f.CreateInstanceWithPanoramaHeadingPitchAndFieldOfView(panorama, headingInDegrees, pitchInDegrees, fieldOfViewInDegrees); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama> StreetsidePanorama::FindNearbyAsync(Windows::Devices::Geolocation::Geopoint const& location)
{
    return impl::call_factory<StreetsidePanorama, Windows::UI::Xaml::Controls::Maps::IStreetsidePanoramaStatics>([&](auto&& f) { return f.FindNearbyAsync(location); });
}

inline Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Controls::Maps::StreetsidePanorama> StreetsidePanorama::FindNearbyAsync(Windows::Devices::Geolocation::Geopoint const& location, double radiusInMeters)
{
    return impl::call_factory<StreetsidePanorama, Windows::UI::Xaml::Controls::Maps::IStreetsidePanoramaStatics>([&](auto&& f) { return f.FindNearbyAsync(location, radiusInMeters); });
}

template <typename D, typename... Interfaces>
struct CustomMapTileDataSourceT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSource, Windows::UI::Xaml::Controls::Maps::IMapTileDataSource, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileDataSource, Windows::UI::Xaml::DependencyObject>
{
    using composable = CustomMapTileDataSource;

protected:
    CustomMapTileDataSourceT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource, Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSourceFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct HttpMapTileDataSourceT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource, Windows::UI::Xaml::Controls::Maps::IMapTileDataSource, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileDataSource, Windows::UI::Xaml::DependencyObject>
{
    using composable = HttpMapTileDataSource;

protected:
    HttpMapTileDataSourceT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource, Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSourceFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
    HttpMapTileDataSourceT(param::hstring const& uriFormatString)
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource, Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSourceFactory>([&](auto&& f) { f.CreateInstanceWithUriFormatString(uriFormatString, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct LocalMapTileDataSourceT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSource, Windows::UI::Xaml::Controls::Maps::IMapTileDataSource, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource, Windows::UI::Xaml::Controls::Maps::MapTileDataSource, Windows::UI::Xaml::DependencyObject>
{
    using composable = LocalMapTileDataSource;

protected:
    LocalMapTileDataSourceT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource, Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSourceFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
    LocalMapTileDataSourceT(param::hstring const& uriFormatString)
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource, Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSourceFactory>([&](auto&& f) { f.CreateInstanceWithUriFormatString(uriFormatString, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MapCustomExperienceT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Maps::IMapCustomExperience, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Maps::MapCustomExperience, Windows::UI::Xaml::DependencyObject>
{
    using composable = MapCustomExperience;

protected:
    MapCustomExperienceT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::MapCustomExperience, Windows::UI::Xaml::Controls::Maps::IMapCustomExperienceFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MapElementT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Maps::IMapElement, Windows::UI::Xaml::Controls::Maps::IMapElement2, Windows::UI::Xaml::Controls::Maps::IMapElement3, Windows::UI::Xaml::Controls::Maps::IMapElement4, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Maps::MapElement, Windows::UI::Xaml::DependencyObject>
{
    using composable = MapElement;

protected:
    MapElementT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::MapElement, Windows::UI::Xaml::Controls::Maps::IMapElementFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MapLayerT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Maps::IMapLayer, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Maps::MapLayer, Windows::UI::Xaml::DependencyObject>
{
    using composable = MapLayer;

protected:
    MapLayerT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::MapLayer, Windows::UI::Xaml::Controls::Maps::IMapLayerFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MapModel3DT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Maps::IMapModel3D, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Maps::MapModel3D, Windows::UI::Xaml::DependencyObject>
{
    using composable = MapModel3D;

protected:
    MapModel3DT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::MapModel3D, Windows::UI::Xaml::Controls::Maps::IMapModel3DFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MapRouteViewT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Maps::IMapRouteView, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Maps::MapRouteView, Windows::UI::Xaml::DependencyObject>
{
    using composable = MapRouteView;

protected:
    MapRouteViewT(Windows::Services::Maps::MapRoute const& route)
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::MapRouteView, Windows::UI::Xaml::Controls::Maps::IMapRouteViewFactory>([&](auto&& f) { f.CreateInstanceWithMapRoute(route, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MapTileDataSourceT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Maps::IMapTileDataSource, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Maps::MapTileDataSource, Windows::UI::Xaml::DependencyObject>
{
    using composable = MapTileDataSource;

protected:
    MapTileDataSourceT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::MapTileDataSource, Windows::UI::Xaml::Controls::Maps::IMapTileDataSourceFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct MapTileSourceT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Controls::Maps::IMapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSource2, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Controls::Maps::MapTileSource, Windows::UI::Xaml::DependencyObject>
{
    using composable = MapTileSource;

protected:
    MapTileSourceT()
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
    MapTileSourceT(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource)
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory>([&](auto&& f) { f.CreateInstanceWithDataSource(dataSource, *this, this->m_inner); });
    }
    MapTileSourceT(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const& zoomLevelRange)
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory>([&](auto&& f) { f.CreateInstanceWithDataSourceAndZoomRange(dataSource, zoomLevelRange, *this, this->m_inner); });
    }
    MapTileSourceT(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const& zoomLevelRange, Windows::Devices::Geolocation::GeoboundingBox const& bounds)
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory>([&](auto&& f) { f.CreateInstanceWithDataSourceZoomRangeAndBounds(dataSource, zoomLevelRange, bounds, *this, this->m_inner); });
    }
    MapTileSourceT(Windows::UI::Xaml::Controls::Maps::MapTileDataSource const& dataSource, Windows::UI::Xaml::Controls::Maps::MapZoomLevelRange const& zoomLevelRange, Windows::Devices::Geolocation::GeoboundingBox const& bounds, int32_t tileSizeInPixels)
    {
        impl::call_factory<Windows::UI::Xaml::Controls::Maps::MapTileSource, Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory>([&](auto&& f) { f.CreateInstanceWithDataSourceZoomRangeBoundsAndTileSize(dataSource, zoomLevelRange, bounds, tileSizeInPixels, *this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::ICustomMapTileDataSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IHttpMapTileDataSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::ILocalMapTileDataSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangingEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapActualCameraChangingEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapBillboard> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapBillboard> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapBillboardFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapBillboardFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapBillboardStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapBillboardStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapCamera> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapCamera> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapCameraFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapCameraFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapContextRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapContextRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl6> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl7> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl7> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl8> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControl8> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkClickEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkClickEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkPointerEnteredEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkPointerEnteredEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkPointerExitedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkPointerExitedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkRightTappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlBusinessLandmarkRightTappedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlDataHelper2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlDataHelperStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics5> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics5> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics6> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics6> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics7> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics7> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics8> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlStatics8> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureClickEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureClickEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerEnteredEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerEnteredEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerExitedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeaturePointerExitedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureRightTappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapControlTransitFeatureRightTappedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapCustomExperience> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapCustomExperience> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapCustomExperienceChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapCustomExperienceChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapCustomExperienceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapCustomExperienceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement3D> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement3D> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement3DStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElement4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementClickEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementClickEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementPointerEnteredEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementPointerEnteredEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementPointerExitedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementPointerExitedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementStatics3> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementStatics3> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementStatics4> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementStatics4> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayerClickEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayerClickEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayerContextRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayerContextRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerEnteredEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerEnteredEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerExitedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayerPointerExitedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapElementsLayerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapIcon> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapIcon> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapIcon2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapIcon2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapIconStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapIconStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapIconStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapIconStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapInputEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapInputEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapItemsControl> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapItemsControl> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapItemsControlStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapItemsControlStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapLayer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapLayer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapLayerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapLayerFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapLayerStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapLayerStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapModel3D> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapModel3D> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapModel3DFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapModel3DFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapModel3DStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapModel3DStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapPolygon> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapPolygon> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapPolygon2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapPolygon2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapPolygonStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapPolygonStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapPolyline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapPolyline> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapPolylineStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapPolylineStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapRightTappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapRightTappedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapRouteView> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapRouteView> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapRouteViewFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapRouteViewFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapScene> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapScene> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapSceneStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapSceneStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapStyleSheet> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapStyleSheet> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntriesStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntryStatesStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapStyleSheetEntryStatesStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapStyleSheetStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTargetCameraChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTargetCameraChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTargetCameraChangedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTargetCameraChangedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequest> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequest> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestDeferral> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestDeferral> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileBitmapRequestedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileDataSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileDataSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileDataSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileDataSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileSource2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileSource2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileSourceStatics2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileUriRequest> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileUriRequest> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestDeferral> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestDeferral> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IMapTileUriRequestedEventArgs2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IStreetsideExperience> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IStreetsideExperience> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IStreetsideExperienceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IStreetsideExperienceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IStreetsidePanorama> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IStreetsidePanorama> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::IStreetsidePanoramaStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::IStreetsidePanoramaStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::CustomMapTileDataSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::HttpMapTileDataSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::LocalMapTileDataSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapActualCameraChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapActualCameraChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapActualCameraChangingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapActualCameraChangingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapBillboard> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapBillboard> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapCamera> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapCamera> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapContextRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapContextRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapControl> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapControl> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkClickEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkClickEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerEnteredEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerEnteredEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerExitedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkPointerExitedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkRightTappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapControlBusinessLandmarkRightTappedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapControlDataHelper> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapControlDataHelper> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureClickEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureClickEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerEnteredEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerEnteredEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerExitedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapControlTransitFeaturePointerExitedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureRightTappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapControlTransitFeatureRightTappedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapCustomExperience> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapCustomExperience> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapCustomExperienceChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapCustomExperienceChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapElement> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapElement> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapElement3D> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapElement3D> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapElementClickEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapElementClickEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapElementPointerEnteredEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapElementPointerEnteredEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapElementPointerExitedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapElementPointerExitedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapElementsLayer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapElementsLayer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapElementsLayerClickEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapElementsLayerClickEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapElementsLayerContextRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapElementsLayerContextRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerEnteredEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerEnteredEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerExitedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapElementsLayerPointerExitedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapIcon> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapIcon> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapInputEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapItemsControl> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapItemsControl> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapLayer> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapLayer> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapModel3D> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapModel3D> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapPolygon> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapPolygon> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapPolyline> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapPolyline> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapRightTappedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapRightTappedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapRouteView> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapRouteView> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapScene> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapScene> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapStyleSheet> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapStyleSheet> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapStyleSheetEntries> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapStyleSheetEntries> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapStyleSheetEntryStates> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapStyleSheetEntryStates> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapTargetCameraChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapTargetCameraChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequest> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequest> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestDeferral> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestDeferral> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapTileBitmapRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapTileDataSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapTileDataSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapTileSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapTileSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapTileUriRequest> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapTileUriRequest> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapTileUriRequestDeferral> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapTileUriRequestDeferral> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::MapTileUriRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::MapTileUriRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::StreetsideExperience> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::StreetsideExperience> {};
template<> struct hash<winrt::Windows::UI::Xaml::Controls::Maps::StreetsidePanorama> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Controls::Maps::StreetsidePanorama> {};

}
