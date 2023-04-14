// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.UI.Popups.2.h"
#include "winrt/impl/Windows.UI.StartScreen.2.h"
#include "winrt/Windows.UI.h"

namespace winrt::impl {

template <typename D> Windows::Foundation::Collections::IVector<Windows::UI::StartScreen::JumpListItem> consume_Windows_UI_StartScreen_IJumpList<D>::Items() const
{
    Windows::Foundation::Collections::IVector<Windows::UI::StartScreen::JumpListItem> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpList)->get_Items(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::StartScreen::JumpListSystemGroupKind consume_Windows_UI_StartScreen_IJumpList<D>::SystemGroupKind() const
{
    Windows::UI::StartScreen::JumpListSystemGroupKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpList)->get_SystemGroupKind(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_IJumpList<D>::SystemGroupKind(Windows::UI::StartScreen::JumpListSystemGroupKind const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpList)->put_SystemGroupKind(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_UI_StartScreen_IJumpList<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncAction result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpList)->SaveAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::StartScreen::JumpListItemKind consume_Windows_UI_StartScreen_IJumpListItem<D>::Kind() const
{
    Windows::UI::StartScreen::JumpListItemKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItem)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_StartScreen_IJumpListItem<D>::Arguments() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItem)->get_Arguments(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_StartScreen_IJumpListItem<D>::RemovedByUser() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItem)->get_RemovedByUser(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_StartScreen_IJumpListItem<D>::Description() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItem)->get_Description(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_IJumpListItem<D>::Description(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItem)->put_Description(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_StartScreen_IJumpListItem<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItem)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_IJumpListItem<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItem)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_StartScreen_IJumpListItem<D>::GroupName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItem)->get_GroupName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_IJumpListItem<D>::GroupName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItem)->put_GroupName(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_IJumpListItem<D>::Logo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItem)->get_Logo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_IJumpListItem<D>::Logo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItem)->put_Logo(get_abi(value)));
}

template <typename D> Windows::UI::StartScreen::JumpListItem consume_Windows_UI_StartScreen_IJumpListItemStatics<D>::CreateWithArguments(param::hstring const& arguments, param::hstring const& displayName) const
{
    Windows::UI::StartScreen::JumpListItem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItemStatics)->CreateWithArguments(get_abi(arguments), get_abi(displayName), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::StartScreen::JumpListItem consume_Windows_UI_StartScreen_IJumpListItemStatics<D>::CreateSeparator() const
{
    Windows::UI::StartScreen::JumpListItem result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListItemStatics)->CreateSeparator(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::StartScreen::JumpList> consume_Windows_UI_StartScreen_IJumpListStatics<D>::LoadCurrentAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::StartScreen::JumpList> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListStatics)->LoadCurrentAsync(put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_UI_StartScreen_IJumpListStatics<D>::IsSupported() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IJumpListStatics)->IsSupported(&result));
    return result;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::TileId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_TileId(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_StartScreen_ISecondaryTile<D>::TileId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_TileId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::Arguments(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_Arguments(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_StartScreen_ISecondaryTile<D>::Arguments() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_Arguments(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::ShortName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_ShortName(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_StartScreen_ISecondaryTile<D>::ShortName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_ShortName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::DisplayName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_DisplayName(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_StartScreen_ISecondaryTile<D>::DisplayName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_DisplayName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::Logo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_Logo(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ISecondaryTile<D>::Logo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_Logo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::SmallLogo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_SmallLogo(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ISecondaryTile<D>::SmallLogo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_SmallLogo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::WideLogo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_WideLogo(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ISecondaryTile<D>::WideLogo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_WideLogo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::LockScreenBadgeLogo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_LockScreenBadgeLogo(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ISecondaryTile<D>::LockScreenBadgeLogo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_LockScreenBadgeLogo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::LockScreenDisplayBadgeAndTileText(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_LockScreenDisplayBadgeAndTileText(value));
}

template <typename D> bool consume_Windows_UI_StartScreen_ISecondaryTile<D>::LockScreenDisplayBadgeAndTileText() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_LockScreenDisplayBadgeAndTileText(&value));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::TileOptions(Windows::UI::StartScreen::TileOptions const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_TileOptions(get_abi(value)));
}

template <typename D> Windows::UI::StartScreen::TileOptions consume_Windows_UI_StartScreen_ISecondaryTile<D>::TileOptions() const
{
    Windows::UI::StartScreen::TileOptions value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_TileOptions(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::ForegroundText(Windows::UI::StartScreen::ForegroundText const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_ForegroundText(get_abi(value)));
}

template <typename D> Windows::UI::StartScreen::ForegroundText consume_Windows_UI_StartScreen_ISecondaryTile<D>::ForegroundText() const
{
    Windows::UI::StartScreen::ForegroundText value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_ForegroundText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile<D>::BackgroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->put_BackgroundColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_StartScreen_ISecondaryTile<D>::BackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_ISecondaryTile<D>::RequestCreateAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->RequestCreateAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_ISecondaryTile<D>::RequestCreateAsync(Windows::Foundation::Point const& invocationPoint) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->RequestCreateAsyncWithPoint(get_abi(invocationPoint), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_ISecondaryTile<D>::RequestCreateForSelectionAsync(Windows::Foundation::Rect const& selection) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->RequestCreateAsyncWithRect(get_abi(selection), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_ISecondaryTile<D>::RequestCreateForSelectionAsync(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->RequestCreateAsyncWithRectAndPlacement(get_abi(selection), get_abi(preferredPlacement), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_ISecondaryTile<D>::RequestDeleteAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->RequestDeleteAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_ISecondaryTile<D>::RequestDeleteAsync(Windows::Foundation::Point const& invocationPoint) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->RequestDeleteAsyncWithPoint(get_abi(invocationPoint), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_ISecondaryTile<D>::RequestDeleteForSelectionAsync(Windows::Foundation::Rect const& selection) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->RequestDeleteAsyncWithRect(get_abi(selection), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_ISecondaryTile<D>::RequestDeleteForSelectionAsync(Windows::Foundation::Rect const& selection, Windows::UI::Popups::Placement const& preferredPlacement) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->RequestDeleteAsyncWithRectAndPlacement(get_abi(selection), get_abi(preferredPlacement), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_ISecondaryTile<D>::UpdateAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile)->UpdateAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile2<D>::PhoneticName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile2)->put_PhoneticName(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_StartScreen_ISecondaryTile2<D>::PhoneticName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile2)->get_PhoneticName(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::StartScreen::SecondaryTileVisualElements consume_Windows_UI_StartScreen_ISecondaryTile2<D>::VisualElements() const
{
    Windows::UI::StartScreen::SecondaryTileVisualElements value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile2)->get_VisualElements(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile2<D>::RoamingEnabled(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile2)->put_RoamingEnabled(value));
}

template <typename D> bool consume_Windows_UI_StartScreen_ISecondaryTile2<D>::RoamingEnabled() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile2)->get_RoamingEnabled(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_StartScreen_ISecondaryTile2<D>::VisualElementsRequested(Windows::Foundation::TypedEventHandler<Windows::UI::StartScreen::SecondaryTile, Windows::UI::StartScreen::VisualElementsRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile2)->add_VisualElementsRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_StartScreen_ISecondaryTile2<D>::VisualElementsRequested_revoker consume_Windows_UI_StartScreen_ISecondaryTile2<D>::VisualElementsRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::UI::StartScreen::SecondaryTile, Windows::UI::StartScreen::VisualElementsRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, VisualElementsRequested_revoker>(this, VisualElementsRequested(handler));
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTile2<D>::VisualElementsRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTile2)->remove_VisualElementsRequested(get_abi(token)));
}

template <typename D> Windows::UI::StartScreen::SecondaryTile consume_Windows_UI_StartScreen_ISecondaryTileFactory<D>::CreateTile(param::hstring const& tileId, param::hstring const& shortName, param::hstring const& displayName, param::hstring const& arguments, Windows::UI::StartScreen::TileOptions const& tileOptions, Windows::Foundation::Uri const& logoReference) const
{
    Windows::UI::StartScreen::SecondaryTile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileFactory)->CreateTile(get_abi(tileId), get_abi(shortName), get_abi(displayName), get_abi(arguments), get_abi(tileOptions), get_abi(logoReference), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::StartScreen::SecondaryTile consume_Windows_UI_StartScreen_ISecondaryTileFactory<D>::CreateWideTile(param::hstring const& tileId, param::hstring const& shortName, param::hstring const& displayName, param::hstring const& arguments, Windows::UI::StartScreen::TileOptions const& tileOptions, Windows::Foundation::Uri const& logoReference, Windows::Foundation::Uri const& wideLogoReference) const
{
    Windows::UI::StartScreen::SecondaryTile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileFactory)->CreateWideTile(get_abi(tileId), get_abi(shortName), get_abi(displayName), get_abi(arguments), get_abi(tileOptions), get_abi(logoReference), get_abi(wideLogoReference), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::StartScreen::SecondaryTile consume_Windows_UI_StartScreen_ISecondaryTileFactory<D>::CreateWithId(param::hstring const& tileId) const
{
    Windows::UI::StartScreen::SecondaryTile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileFactory)->CreateWithId(get_abi(tileId), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::StartScreen::SecondaryTile consume_Windows_UI_StartScreen_ISecondaryTileFactory2<D>::CreateMinimalTile(param::hstring const& tileId, param::hstring const& displayName, param::hstring const& arguments, Windows::Foundation::Uri const& square150x150Logo, Windows::UI::StartScreen::TileSize const& desiredSize) const
{
    Windows::UI::StartScreen::SecondaryTile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileFactory2)->CreateMinimalTile(get_abi(tileId), get_abi(displayName), get_abi(arguments), get_abi(square150x150Logo), get_abi(desiredSize), put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_StartScreen_ISecondaryTileStatics<D>::Exists(param::hstring const& tileId) const
{
    bool exists{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileStatics)->Exists(get_abi(tileId), &exists));
    return exists;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>> consume_Windows_UI_StartScreen_ISecondaryTileStatics<D>::FindAllAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileStatics)->FindAllAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>> consume_Windows_UI_StartScreen_ISecondaryTileStatics<D>::FindAllAsync(param::hstring const& applicationId) const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileStatics)->FindAllForApplicationAsync(get_abi(applicationId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>> consume_Windows_UI_StartScreen_ISecondaryTileStatics<D>::FindAllForPackageAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileStatics)->FindAllForPackageAsync(put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::Square30x30Logo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->put_Square30x30Logo(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::Square30x30Logo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->get_Square30x30Logo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::Square70x70Logo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->put_Square70x70Logo(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::Square70x70Logo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->get_Square70x70Logo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::Square150x150Logo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->put_Square150x150Logo(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::Square150x150Logo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->get_Square150x150Logo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::Wide310x150Logo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->put_Wide310x150Logo(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::Wide310x150Logo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->get_Wide310x150Logo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::Square310x310Logo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->put_Square310x310Logo(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::Square310x310Logo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->get_Square310x310Logo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::ForegroundText(Windows::UI::StartScreen::ForegroundText const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->put_ForegroundText(get_abi(value)));
}

template <typename D> Windows::UI::StartScreen::ForegroundText consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::ForegroundText() const
{
    Windows::UI::StartScreen::ForegroundText value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->get_ForegroundText(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::BackgroundColor(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->put_BackgroundColor(get_abi(value)));
}

template <typename D> Windows::UI::Color consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::BackgroundColor() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->get_BackgroundColor(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::ShowNameOnSquare150x150Logo(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->put_ShowNameOnSquare150x150Logo(value));
}

template <typename D> bool consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::ShowNameOnSquare150x150Logo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->get_ShowNameOnSquare150x150Logo(&value));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::ShowNameOnWide310x150Logo(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->put_ShowNameOnWide310x150Logo(value));
}

template <typename D> bool consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::ShowNameOnWide310x150Logo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->get_ShowNameOnWide310x150Logo(&value));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::ShowNameOnSquare310x310Logo(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->put_ShowNameOnSquare310x310Logo(value));
}

template <typename D> bool consume_Windows_UI_StartScreen_ISecondaryTileVisualElements<D>::ShowNameOnSquare310x310Logo() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements)->get_ShowNameOnSquare310x310Logo(&value));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements2<D>::Square71x71Logo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements2)->put_Square71x71Logo(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ISecondaryTileVisualElements2<D>::Square71x71Logo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements2)->get_Square71x71Logo(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ISecondaryTileVisualElements3<D>::Square44x44Logo(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements3)->put_Square44x44Logo(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ISecondaryTileVisualElements3<D>::Square44x44Logo() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements3)->get_Square44x44Logo(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::StartScreen::TileMixedRealityModel consume_Windows_UI_StartScreen_ISecondaryTileVisualElements4<D>::MixedRealityModel() const
{
    Windows::UI::StartScreen::TileMixedRealityModel value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ISecondaryTileVisualElements4)->get_MixedRealityModel(put_abi(value)));
    return value;
}

template <typename D> Windows::System::User consume_Windows_UI_StartScreen_IStartScreenManager<D>::User() const
{
    Windows::System::User value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IStartScreenManager)->get_User(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_StartScreen_IStartScreenManager<D>::SupportsAppListEntry(Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IStartScreenManager)->SupportsAppListEntry(get_abi(appListEntry), &result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_IStartScreenManager<D>::ContainsAppListEntryAsync(Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IStartScreenManager)->ContainsAppListEntryAsync(get_abi(appListEntry), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_IStartScreenManager<D>::RequestAddAppListEntryAsync(Windows::ApplicationModel::Core::AppListEntry const& appListEntry) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IStartScreenManager)->RequestAddAppListEntryAsync(get_abi(appListEntry), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_IStartScreenManager2<D>::ContainsSecondaryTileAsync(param::hstring const& tileId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IStartScreenManager2)->ContainsSecondaryTileAsync(get_abi(tileId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_UI_StartScreen_IStartScreenManager2<D>::TryRemoveSecondaryTileAsync(param::hstring const& tileId) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IStartScreenManager2)->TryRemoveSecondaryTileAsync(get_abi(tileId), put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::StartScreen::StartScreenManager consume_Windows_UI_StartScreen_IStartScreenManagerStatics<D>::GetDefault() const
{
    Windows::UI::StartScreen::StartScreenManager value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IStartScreenManagerStatics)->GetDefault(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::StartScreen::StartScreenManager consume_Windows_UI_StartScreen_IStartScreenManagerStatics<D>::GetForUser(Windows::System::User const& user) const
{
    Windows::UI::StartScreen::StartScreenManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IStartScreenManagerStatics)->GetForUser(get_abi(user), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_StartScreen_ITileMixedRealityModel<D>::Uri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ITileMixedRealityModel)->put_Uri(get_abi(value)));
}

template <typename D> Windows::Foundation::Uri consume_Windows_UI_StartScreen_ITileMixedRealityModel<D>::Uri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ITileMixedRealityModel)->get_Uri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ITileMixedRealityModel<D>::BoundingBox(optional<Windows::Perception::Spatial::SpatialBoundingBox> const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ITileMixedRealityModel)->put_BoundingBox(get_abi(value)));
}

template <typename D> Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingBox> consume_Windows_UI_StartScreen_ITileMixedRealityModel<D>::BoundingBox() const
{
    Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingBox> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ITileMixedRealityModel)->get_BoundingBox(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_StartScreen_ITileMixedRealityModel2<D>::ActivationBehavior(Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ITileMixedRealityModel2)->put_ActivationBehavior(get_abi(value)));
}

template <typename D> Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior consume_Windows_UI_StartScreen_ITileMixedRealityModel2<D>::ActivationBehavior() const
{
    Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::ITileMixedRealityModel2)->get_ActivationBehavior(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::StartScreen::SecondaryTileVisualElements consume_Windows_UI_StartScreen_IVisualElementsRequest<D>::VisualElements() const
{
    Windows::UI::StartScreen::SecondaryTileVisualElements value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IVisualElementsRequest)->get_VisualElements(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTileVisualElements> consume_Windows_UI_StartScreen_IVisualElementsRequest<D>::AlternateVisualElements() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTileVisualElements> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IVisualElementsRequest)->get_AlternateVisualElements(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::DateTime consume_Windows_UI_StartScreen_IVisualElementsRequest<D>::Deadline() const
{
    Windows::Foundation::DateTime value{};
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IVisualElementsRequest)->get_Deadline(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::StartScreen::VisualElementsRequestDeferral consume_Windows_UI_StartScreen_IVisualElementsRequest<D>::GetDeferral() const
{
    Windows::UI::StartScreen::VisualElementsRequestDeferral deferral{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IVisualElementsRequest)->GetDeferral(put_abi(deferral)));
    return deferral;
}

template <typename D> void consume_Windows_UI_StartScreen_IVisualElementsRequestDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IVisualElementsRequestDeferral)->Complete());
}

template <typename D> Windows::UI::StartScreen::VisualElementsRequest consume_Windows_UI_StartScreen_IVisualElementsRequestedEventArgs<D>::Request() const
{
    Windows::UI::StartScreen::VisualElementsRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::StartScreen::IVisualElementsRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D>
struct produce<D, Windows::UI::StartScreen::IJumpList> : produce_base<D, Windows::UI::StartScreen::IJumpList>
{
    int32_t WINRT_CALL get_Items(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Items, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::UI::StartScreen::JumpListItem>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::UI::StartScreen::JumpListItem>>(this->shim().Items());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SystemGroupKind(Windows::UI::StartScreen::JumpListSystemGroupKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemGroupKind, WINRT_WRAP(Windows::UI::StartScreen::JumpListSystemGroupKind));
            *value = detach_from<Windows::UI::StartScreen::JumpListSystemGroupKind>(this->shim().SystemGroupKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SystemGroupKind(Windows::UI::StartScreen::JumpListSystemGroupKind value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SystemGroupKind, WINRT_WRAP(void), Windows::UI::StartScreen::JumpListSystemGroupKind const&);
            this->shim().SystemGroupKind(*reinterpret_cast<Windows::UI::StartScreen::JumpListSystemGroupKind const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *result = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::IJumpListItem> : produce_base<D, Windows::UI::StartScreen::IJumpListItem>
{
    int32_t WINRT_CALL get_Kind(Windows::UI::StartScreen::JumpListItemKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::UI::StartScreen::JumpListItemKind));
            *value = detach_from<Windows::UI::StartScreen::JumpListItemKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Arguments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Arguments, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Arguments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RemovedByUser(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemovedByUser, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RemovedByUser());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Description(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Description(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Description, WINRT_WRAP(void), hstring const&);
            this->shim().Description(*reinterpret_cast<hstring const*>(&value));
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

    int32_t WINRT_CALL get_GroupName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GroupName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().GroupName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_GroupName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GroupName, WINRT_WRAP(void), hstring const&);
            this->shim().GroupName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Logo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Logo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::IJumpListItemStatics> : produce_base<D, Windows::UI::StartScreen::IJumpListItemStatics>
{
    int32_t WINRT_CALL CreateWithArguments(void* arguments, void* displayName, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithArguments, WINRT_WRAP(Windows::UI::StartScreen::JumpListItem), hstring const&, hstring const&);
            *result = detach_from<Windows::UI::StartScreen::JumpListItem>(this->shim().CreateWithArguments(*reinterpret_cast<hstring const*>(&arguments), *reinterpret_cast<hstring const*>(&displayName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateSeparator(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateSeparator, WINRT_WRAP(Windows::UI::StartScreen::JumpListItem));
            *result = detach_from<Windows::UI::StartScreen::JumpListItem>(this->shim().CreateSeparator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::IJumpListStatics> : produce_base<D, Windows::UI::StartScreen::IJumpListStatics>
{
    int32_t WINRT_CALL LoadCurrentAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadCurrentAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::StartScreen::JumpList>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::StartScreen::JumpList>>(this->shim().LoadCurrentAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsSupported(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSupported, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().IsSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::ISecondaryTile> : produce_base<D, Windows::UI::StartScreen::ISecondaryTile>
{
    int32_t WINRT_CALL put_TileId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TileId, WINRT_WRAP(void), hstring const&);
            this->shim().TileId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TileId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TileId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().TileId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Arguments(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Arguments, WINRT_WRAP(void), hstring const&);
            this->shim().Arguments(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Arguments(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Arguments, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Arguments());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShortName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShortName, WINRT_WRAP(void), hstring const&);
            this->shim().ShortName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShortName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShortName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ShortName());
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

    int32_t WINRT_CALL put_Logo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Logo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Logo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_SmallLogo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmallLogo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().SmallLogo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_SmallLogo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SmallLogo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().SmallLogo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_WideLogo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WideLogo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().WideLogo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_WideLogo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(WideLogo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().WideLogo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LockScreenBadgeLogo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LockScreenBadgeLogo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().LockScreenBadgeLogo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LockScreenBadgeLogo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LockScreenBadgeLogo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().LockScreenBadgeLogo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_LockScreenDisplayBadgeAndTileText(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LockScreenDisplayBadgeAndTileText, WINRT_WRAP(void), bool);
            this->shim().LockScreenDisplayBadgeAndTileText(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LockScreenDisplayBadgeAndTileText(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LockScreenDisplayBadgeAndTileText, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().LockScreenDisplayBadgeAndTileText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TileOptions(Windows::UI::StartScreen::TileOptions value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TileOptions, WINRT_WRAP(void), Windows::UI::StartScreen::TileOptions const&);
            this->shim().TileOptions(*reinterpret_cast<Windows::UI::StartScreen::TileOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TileOptions(Windows::UI::StartScreen::TileOptions* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TileOptions, WINRT_WRAP(Windows::UI::StartScreen::TileOptions));
            *value = detach_from<Windows::UI::StartScreen::TileOptions>(this->shim().TileOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ForegroundText(Windows::UI::StartScreen::ForegroundText value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundText, WINRT_WRAP(void), Windows::UI::StartScreen::ForegroundText const&);
            this->shim().ForegroundText(*reinterpret_cast<Windows::UI::StartScreen::ForegroundText const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForegroundText(Windows::UI::StartScreen::ForegroundText* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundText, WINRT_WRAP(Windows::UI::StartScreen::ForegroundText));
            *value = detach_from<Windows::UI::StartScreen::ForegroundText>(this->shim().ForegroundText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().BackgroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestCreateAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestCreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestCreateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestCreateAsyncWithPoint(Windows::Foundation::Point invocationPoint, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestCreateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Point const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestCreateAsync(*reinterpret_cast<Windows::Foundation::Point const*>(&invocationPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestCreateAsyncWithRect(Windows::Foundation::Rect selection, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestCreateForSelectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Rect const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestCreateForSelectionAsync(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestCreateAsyncWithRectAndPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestCreateForSelectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Rect const, Windows::UI::Popups::Placement const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestCreateForSelectionAsync(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&preferredPlacement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestDeleteAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestDeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestDeleteAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestDeleteAsyncWithPoint(Windows::Foundation::Point invocationPoint, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestDeleteAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Point const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestDeleteAsync(*reinterpret_cast<Windows::Foundation::Point const*>(&invocationPoint)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestDeleteAsyncWithRect(Windows::Foundation::Rect selection, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestDeleteForSelectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Rect const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestDeleteForSelectionAsync(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestDeleteAsyncWithRectAndPlacement(Windows::Foundation::Rect selection, Windows::UI::Popups::Placement preferredPlacement, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestDeleteForSelectionAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::Rect const, Windows::UI::Popups::Placement const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestDeleteForSelectionAsync(*reinterpret_cast<Windows::Foundation::Rect const*>(&selection), *reinterpret_cast<Windows::UI::Popups::Placement const*>(&preferredPlacement)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().UpdateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::ISecondaryTile2> : produce_base<D, Windows::UI::StartScreen::ISecondaryTile2>
{
    int32_t WINRT_CALL put_PhoneticName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneticName, WINRT_WRAP(void), hstring const&);
            this->shim().PhoneticName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PhoneticName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PhoneticName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PhoneticName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VisualElements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisualElements, WINRT_WRAP(Windows::UI::StartScreen::SecondaryTileVisualElements));
            *value = detach_from<Windows::UI::StartScreen::SecondaryTileVisualElements>(this->shim().VisualElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RoamingEnabled(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoamingEnabled, WINRT_WRAP(void), bool);
            this->shim().RoamingEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RoamingEnabled(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RoamingEnabled, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().RoamingEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_VisualElementsRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisualElementsRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::UI::StartScreen::SecondaryTile, Windows::UI::StartScreen::VisualElementsRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().VisualElementsRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::UI::StartScreen::SecondaryTile, Windows::UI::StartScreen::VisualElementsRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_VisualElementsRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(VisualElementsRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().VisualElementsRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::ISecondaryTileFactory> : produce_base<D, Windows::UI::StartScreen::ISecondaryTileFactory>
{
    int32_t WINRT_CALL CreateTile(void* tileId, void* shortName, void* displayName, void* arguments, Windows::UI::StartScreen::TileOptions tileOptions, void* logoReference, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTile, WINRT_WRAP(Windows::UI::StartScreen::SecondaryTile), hstring const&, hstring const&, hstring const&, hstring const&, Windows::UI::StartScreen::TileOptions const&, Windows::Foundation::Uri const&);
            *value = detach_from<Windows::UI::StartScreen::SecondaryTile>(this->shim().CreateTile(*reinterpret_cast<hstring const*>(&tileId), *reinterpret_cast<hstring const*>(&shortName), *reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<hstring const*>(&arguments), *reinterpret_cast<Windows::UI::StartScreen::TileOptions const*>(&tileOptions), *reinterpret_cast<Windows::Foundation::Uri const*>(&logoReference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWideTile(void* tileId, void* shortName, void* displayName, void* arguments, Windows::UI::StartScreen::TileOptions tileOptions, void* logoReference, void* wideLogoReference, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWideTile, WINRT_WRAP(Windows::UI::StartScreen::SecondaryTile), hstring const&, hstring const&, hstring const&, hstring const&, Windows::UI::StartScreen::TileOptions const&, Windows::Foundation::Uri const&, Windows::Foundation::Uri const&);
            *value = detach_from<Windows::UI::StartScreen::SecondaryTile>(this->shim().CreateWideTile(*reinterpret_cast<hstring const*>(&tileId), *reinterpret_cast<hstring const*>(&shortName), *reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<hstring const*>(&arguments), *reinterpret_cast<Windows::UI::StartScreen::TileOptions const*>(&tileOptions), *reinterpret_cast<Windows::Foundation::Uri const*>(&logoReference), *reinterpret_cast<Windows::Foundation::Uri const*>(&wideLogoReference)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithId(void* tileId, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateWithId, WINRT_WRAP(Windows::UI::StartScreen::SecondaryTile), hstring const&);
            *value = detach_from<Windows::UI::StartScreen::SecondaryTile>(this->shim().CreateWithId(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::ISecondaryTileFactory2> : produce_base<D, Windows::UI::StartScreen::ISecondaryTileFactory2>
{
    int32_t WINRT_CALL CreateMinimalTile(void* tileId, void* displayName, void* arguments, void* square150x150Logo, Windows::UI::StartScreen::TileSize desiredSize, void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateMinimalTile, WINRT_WRAP(Windows::UI::StartScreen::SecondaryTile), hstring const&, hstring const&, hstring const&, Windows::Foundation::Uri const&, Windows::UI::StartScreen::TileSize const&);
            *value = detach_from<Windows::UI::StartScreen::SecondaryTile>(this->shim().CreateMinimalTile(*reinterpret_cast<hstring const*>(&tileId), *reinterpret_cast<hstring const*>(&displayName), *reinterpret_cast<hstring const*>(&arguments), *reinterpret_cast<Windows::Foundation::Uri const*>(&square150x150Logo), *reinterpret_cast<Windows::UI::StartScreen::TileSize const*>(&desiredSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::ISecondaryTileStatics> : produce_base<D, Windows::UI::StartScreen::ISecondaryTileStatics>
{
    int32_t WINRT_CALL Exists(void* tileId, bool* exists) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Exists, WINRT_WRAP(bool), hstring const&);
            *exists = detach_from<bool>(this->shim().Exists(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllForApplicationAsync(void* applicationId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>>>(this->shim().FindAllAsync(*reinterpret_cast<hstring const*>(&applicationId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindAllForPackageAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindAllForPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>>>(this->shim().FindAllForPackageAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::ISecondaryTileVisualElements> : produce_base<D, Windows::UI::StartScreen::ISecondaryTileVisualElements>
{
    int32_t WINRT_CALL put_Square30x30Logo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square30x30Logo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Square30x30Logo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Square30x30Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square30x30Logo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Square30x30Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Square70x70Logo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square70x70Logo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Square70x70Logo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Square70x70Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square70x70Logo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Square70x70Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Square150x150Logo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square150x150Logo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Square150x150Logo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Square150x150Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square150x150Logo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Square150x150Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Wide310x150Logo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wide310x150Logo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Wide310x150Logo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Wide310x150Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Wide310x150Logo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Wide310x150Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Square310x310Logo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square310x310Logo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Square310x310Logo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Square310x310Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square310x310Logo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Square310x310Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ForegroundText(Windows::UI::StartScreen::ForegroundText value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundText, WINRT_WRAP(void), Windows::UI::StartScreen::ForegroundText const&);
            this->shim().ForegroundText(*reinterpret_cast<Windows::UI::StartScreen::ForegroundText const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ForegroundText(Windows::UI::StartScreen::ForegroundText* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ForegroundText, WINRT_WRAP(Windows::UI::StartScreen::ForegroundText));
            *value = detach_from<Windows::UI::StartScreen::ForegroundText>(this->shim().ForegroundText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BackgroundColor(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().BackgroundColor(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BackgroundColor(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BackgroundColor, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().BackgroundColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShowNameOnSquare150x150Logo(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowNameOnSquare150x150Logo, WINRT_WRAP(void), bool);
            this->shim().ShowNameOnSquare150x150Logo(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShowNameOnSquare150x150Logo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowNameOnSquare150x150Logo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShowNameOnSquare150x150Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShowNameOnWide310x150Logo(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowNameOnWide310x150Logo, WINRT_WRAP(void), bool);
            this->shim().ShowNameOnWide310x150Logo(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShowNameOnWide310x150Logo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowNameOnWide310x150Logo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShowNameOnWide310x150Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShowNameOnSquare310x310Logo(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowNameOnSquare310x310Logo, WINRT_WRAP(void), bool);
            this->shim().ShowNameOnSquare310x310Logo(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShowNameOnSquare310x310Logo(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowNameOnSquare310x310Logo, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShowNameOnSquare310x310Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::ISecondaryTileVisualElements2> : produce_base<D, Windows::UI::StartScreen::ISecondaryTileVisualElements2>
{
    int32_t WINRT_CALL put_Square71x71Logo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square71x71Logo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Square71x71Logo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Square71x71Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square71x71Logo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Square71x71Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::ISecondaryTileVisualElements3> : produce_base<D, Windows::UI::StartScreen::ISecondaryTileVisualElements3>
{
    int32_t WINRT_CALL put_Square44x44Logo(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square44x44Logo, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().Square44x44Logo(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Square44x44Logo(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Square44x44Logo, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().Square44x44Logo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::ISecondaryTileVisualElements4> : produce_base<D, Windows::UI::StartScreen::ISecondaryTileVisualElements4>
{
    int32_t WINRT_CALL get_MixedRealityModel(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MixedRealityModel, WINRT_WRAP(Windows::UI::StartScreen::TileMixedRealityModel));
            *value = detach_from<Windows::UI::StartScreen::TileMixedRealityModel>(this->shim().MixedRealityModel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::IStartScreenManager> : produce_base<D, Windows::UI::StartScreen::IStartScreenManager>
{
    int32_t WINRT_CALL get_User(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(User, WINRT_WRAP(Windows::System::User));
            *value = detach_from<Windows::System::User>(this->shim().User());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SupportsAppListEntry(void* appListEntry, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SupportsAppListEntry, WINRT_WRAP(bool), Windows::ApplicationModel::Core::AppListEntry const&);
            *result = detach_from<bool>(this->shim().SupportsAppListEntry(*reinterpret_cast<Windows::ApplicationModel::Core::AppListEntry const*>(&appListEntry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ContainsAppListEntryAsync(void* appListEntry, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContainsAppListEntryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Core::AppListEntry const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().ContainsAppListEntryAsync(*reinterpret_cast<Windows::ApplicationModel::Core::AppListEntry const*>(&appListEntry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RequestAddAppListEntryAsync(void* appListEntry, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequestAddAppListEntryAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::ApplicationModel::Core::AppListEntry const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestAddAppListEntryAsync(*reinterpret_cast<Windows::ApplicationModel::Core::AppListEntry const*>(&appListEntry)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::IStartScreenManager2> : produce_base<D, Windows::UI::StartScreen::IStartScreenManager2>
{
    int32_t WINRT_CALL ContainsSecondaryTileAsync(void* tileId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContainsSecondaryTileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().ContainsSecondaryTileAsync(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryRemoveSecondaryTileAsync(void* tileId, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryRemoveSecondaryTileAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), hstring const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryRemoveSecondaryTileAsync(*reinterpret_cast<hstring const*>(&tileId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::IStartScreenManagerStatics> : produce_base<D, Windows::UI::StartScreen::IStartScreenManagerStatics>
{
    int32_t WINRT_CALL GetDefault(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDefault, WINRT_WRAP(Windows::UI::StartScreen::StartScreenManager));
            *value = detach_from<Windows::UI::StartScreen::StartScreenManager>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetForUser(void* user, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForUser, WINRT_WRAP(Windows::UI::StartScreen::StartScreenManager), Windows::System::User const&);
            *result = detach_from<Windows::UI::StartScreen::StartScreenManager>(this->shim().GetForUser(*reinterpret_cast<Windows::System::User const*>(&user)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::ITileMixedRealityModel> : produce_base<D, Windows::UI::StartScreen::ITileMixedRealityModel>
{
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

    int32_t WINRT_CALL put_BoundingBox(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingBox, WINRT_WRAP(void), Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingBox> const&);
            this->shim().BoundingBox(*reinterpret_cast<Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingBox> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BoundingBox(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingBox, WINRT_WRAP(Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingBox>));
            *value = detach_from<Windows::Foundation::IReference<Windows::Perception::Spatial::SpatialBoundingBox>>(this->shim().BoundingBox());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::ITileMixedRealityModel2> : produce_base<D, Windows::UI::StartScreen::ITileMixedRealityModel2>
{
    int32_t WINRT_CALL put_ActivationBehavior(Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivationBehavior, WINRT_WRAP(void), Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior const&);
            this->shim().ActivationBehavior(*reinterpret_cast<Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ActivationBehavior(Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ActivationBehavior, WINRT_WRAP(Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior));
            *value = detach_from<Windows::UI::StartScreen::TileMixedRealityModelActivationBehavior>(this->shim().ActivationBehavior());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::IVisualElementsRequest> : produce_base<D, Windows::UI::StartScreen::IVisualElementsRequest>
{
    int32_t WINRT_CALL get_VisualElements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VisualElements, WINRT_WRAP(Windows::UI::StartScreen::SecondaryTileVisualElements));
            *value = detach_from<Windows::UI::StartScreen::SecondaryTileVisualElements>(this->shim().VisualElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AlternateVisualElements(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AlternateVisualElements, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTileVisualElements>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTileVisualElements>>(this->shim().AlternateVisualElements());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Deadline(Windows::Foundation::DateTime* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Deadline, WINRT_WRAP(Windows::Foundation::DateTime));
            *value = detach_from<Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** deferral) noexcept final
    {
        try
        {
            *deferral = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::UI::StartScreen::VisualElementsRequestDeferral));
            *deferral = detach_from<Windows::UI::StartScreen::VisualElementsRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::StartScreen::IVisualElementsRequestDeferral> : produce_base<D, Windows::UI::StartScreen::IVisualElementsRequestDeferral>
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
struct produce<D, Windows::UI::StartScreen::IVisualElementsRequestedEventArgs> : produce_base<D, Windows::UI::StartScreen::IVisualElementsRequestedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::UI::StartScreen::VisualElementsRequest));
            *value = detach_from<Windows::UI::StartScreen::VisualElementsRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::StartScreen {

inline Windows::Foundation::IAsyncOperation<Windows::UI::StartScreen::JumpList> JumpList::LoadCurrentAsync()
{
    return impl::call_factory<JumpList, Windows::UI::StartScreen::IJumpListStatics>([&](auto&& f) { return f.LoadCurrentAsync(); });
}

inline bool JumpList::IsSupported()
{
    return impl::call_factory<JumpList, Windows::UI::StartScreen::IJumpListStatics>([&](auto&& f) { return f.IsSupported(); });
}

inline Windows::UI::StartScreen::JumpListItem JumpListItem::CreateWithArguments(param::hstring const& arguments, param::hstring const& displayName)
{
    return impl::call_factory<JumpListItem, Windows::UI::StartScreen::IJumpListItemStatics>([&](auto&& f) { return f.CreateWithArguments(arguments, displayName); });
}

inline Windows::UI::StartScreen::JumpListItem JumpListItem::CreateSeparator()
{
    return impl::call_factory<JumpListItem, Windows::UI::StartScreen::IJumpListItemStatics>([&](auto&& f) { return f.CreateSeparator(); });
}

inline SecondaryTile::SecondaryTile() :
    SecondaryTile(impl::call_factory<SecondaryTile>([](auto&& f) { return f.template ActivateInstance<SecondaryTile>(); }))
{}

inline SecondaryTile::SecondaryTile(param::hstring const& tileId, param::hstring const& shortName, param::hstring const& displayName, param::hstring const& arguments, Windows::UI::StartScreen::TileOptions const& tileOptions, Windows::Foundation::Uri const& logoReference) :
    SecondaryTile(impl::call_factory<SecondaryTile, Windows::UI::StartScreen::ISecondaryTileFactory>([&](auto&& f) { return f.CreateTile(tileId, shortName, displayName, arguments, tileOptions, logoReference); }))
{}

inline SecondaryTile::SecondaryTile(param::hstring const& tileId, param::hstring const& shortName, param::hstring const& displayName, param::hstring const& arguments, Windows::UI::StartScreen::TileOptions const& tileOptions, Windows::Foundation::Uri const& logoReference, Windows::Foundation::Uri const& wideLogoReference) :
    SecondaryTile(impl::call_factory<SecondaryTile, Windows::UI::StartScreen::ISecondaryTileFactory>([&](auto&& f) { return f.CreateWideTile(tileId, shortName, displayName, arguments, tileOptions, logoReference, wideLogoReference); }))
{}

inline SecondaryTile::SecondaryTile(param::hstring const& tileId) :
    SecondaryTile(impl::call_factory<SecondaryTile, Windows::UI::StartScreen::ISecondaryTileFactory>([&](auto&& f) { return f.CreateWithId(tileId); }))
{}

inline SecondaryTile::SecondaryTile(param::hstring const& tileId, param::hstring const& displayName, param::hstring const& arguments, Windows::Foundation::Uri const& square150x150Logo, Windows::UI::StartScreen::TileSize const& desiredSize) :
    SecondaryTile(impl::call_factory<SecondaryTile, Windows::UI::StartScreen::ISecondaryTileFactory2>([&](auto&& f) { return f.CreateMinimalTile(tileId, displayName, arguments, square150x150Logo, desiredSize); }))
{}

inline bool SecondaryTile::Exists(param::hstring const& tileId)
{
    return impl::call_factory<SecondaryTile, Windows::UI::StartScreen::ISecondaryTileStatics>([&](auto&& f) { return f.Exists(tileId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>> SecondaryTile::FindAllAsync()
{
    return impl::call_factory<SecondaryTile, Windows::UI::StartScreen::ISecondaryTileStatics>([&](auto&& f) { return f.FindAllAsync(); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>> SecondaryTile::FindAllAsync(param::hstring const& applicationId)
{
    return impl::call_factory<SecondaryTile, Windows::UI::StartScreen::ISecondaryTileStatics>([&](auto&& f) { return f.FindAllAsync(applicationId); });
}

inline Windows::Foundation::IAsyncOperation<Windows::Foundation::Collections::IVectorView<Windows::UI::StartScreen::SecondaryTile>> SecondaryTile::FindAllForPackageAsync()
{
    return impl::call_factory<SecondaryTile, Windows::UI::StartScreen::ISecondaryTileStatics>([&](auto&& f) { return f.FindAllForPackageAsync(); });
}

inline Windows::UI::StartScreen::StartScreenManager StartScreenManager::GetDefault()
{
    return impl::call_factory<StartScreenManager, Windows::UI::StartScreen::IStartScreenManagerStatics>([&](auto&& f) { return f.GetDefault(); });
}

inline Windows::UI::StartScreen::StartScreenManager StartScreenManager::GetForUser(Windows::System::User const& user)
{
    return impl::call_factory<StartScreenManager, Windows::UI::StartScreen::IStartScreenManagerStatics>([&](auto&& f) { return f.GetForUser(user); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::StartScreen::IJumpList> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::IJumpList> {};
template<> struct hash<winrt::Windows::UI::StartScreen::IJumpListItem> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::IJumpListItem> {};
template<> struct hash<winrt::Windows::UI::StartScreen::IJumpListItemStatics> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::IJumpListItemStatics> {};
template<> struct hash<winrt::Windows::UI::StartScreen::IJumpListStatics> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::IJumpListStatics> {};
template<> struct hash<winrt::Windows::UI::StartScreen::ISecondaryTile> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::ISecondaryTile> {};
template<> struct hash<winrt::Windows::UI::StartScreen::ISecondaryTile2> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::ISecondaryTile2> {};
template<> struct hash<winrt::Windows::UI::StartScreen::ISecondaryTileFactory> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::ISecondaryTileFactory> {};
template<> struct hash<winrt::Windows::UI::StartScreen::ISecondaryTileFactory2> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::ISecondaryTileFactory2> {};
template<> struct hash<winrt::Windows::UI::StartScreen::ISecondaryTileStatics> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::ISecondaryTileStatics> {};
template<> struct hash<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements> {};
template<> struct hash<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements2> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements2> {};
template<> struct hash<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements3> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements3> {};
template<> struct hash<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements4> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::ISecondaryTileVisualElements4> {};
template<> struct hash<winrt::Windows::UI::StartScreen::IStartScreenManager> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::IStartScreenManager> {};
template<> struct hash<winrt::Windows::UI::StartScreen::IStartScreenManager2> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::IStartScreenManager2> {};
template<> struct hash<winrt::Windows::UI::StartScreen::IStartScreenManagerStatics> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::IStartScreenManagerStatics> {};
template<> struct hash<winrt::Windows::UI::StartScreen::ITileMixedRealityModel> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::ITileMixedRealityModel> {};
template<> struct hash<winrt::Windows::UI::StartScreen::ITileMixedRealityModel2> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::ITileMixedRealityModel2> {};
template<> struct hash<winrt::Windows::UI::StartScreen::IVisualElementsRequest> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::IVisualElementsRequest> {};
template<> struct hash<winrt::Windows::UI::StartScreen::IVisualElementsRequestDeferral> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::IVisualElementsRequestDeferral> {};
template<> struct hash<winrt::Windows::UI::StartScreen::IVisualElementsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::IVisualElementsRequestedEventArgs> {};
template<> struct hash<winrt::Windows::UI::StartScreen::JumpList> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::JumpList> {};
template<> struct hash<winrt::Windows::UI::StartScreen::JumpListItem> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::JumpListItem> {};
template<> struct hash<winrt::Windows::UI::StartScreen::SecondaryTile> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::SecondaryTile> {};
template<> struct hash<winrt::Windows::UI::StartScreen::SecondaryTileVisualElements> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::SecondaryTileVisualElements> {};
template<> struct hash<winrt::Windows::UI::StartScreen::StartScreenManager> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::StartScreenManager> {};
template<> struct hash<winrt::Windows::UI::StartScreen::TileMixedRealityModel> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::TileMixedRealityModel> {};
template<> struct hash<winrt::Windows::UI::StartScreen::VisualElementsRequest> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::VisualElementsRequest> {};
template<> struct hash<winrt::Windows::UI::StartScreen::VisualElementsRequestDeferral> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::VisualElementsRequestDeferral> {};
template<> struct hash<winrt::Windows::UI::StartScreen::VisualElementsRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::StartScreen::VisualElementsRequestedEventArgs> {};

}
