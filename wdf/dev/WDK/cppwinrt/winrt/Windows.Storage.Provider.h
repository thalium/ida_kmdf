// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Storage.Provider.2.h"
#include "winrt/Windows.Storage.h"

namespace winrt::impl {

template <typename D> void consume_Windows_Storage_Provider_ICachedFileUpdaterStatics<D>::SetUpdateInformation(Windows::Storage::IStorageFile const& file, param::hstring const& contentId, Windows::Storage::Provider::ReadActivationMode const& readMode, Windows::Storage::Provider::WriteActivationMode const& writeMode, Windows::Storage::Provider::CachedFileOptions const& options) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::ICachedFileUpdaterStatics)->SetUpdateInformation(get_abi(file), get_abi(contentId), get_abi(readMode), get_abi(writeMode), get_abi(options)));
}

template <typename D> hstring consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::Title() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::ICachedFileUpdaterUI)->get_Title(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::Title(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::ICachedFileUpdaterUI)->put_Title(get_abi(value)));
}

template <typename D> Windows::Storage::Provider::CachedFileTarget consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UpdateTarget() const
{
    Windows::Storage::Provider::CachedFileTarget value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::ICachedFileUpdaterUI)->get_UpdateTarget(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::FileUpdateRequested(Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Storage::Provider::FileUpdateRequestedEventArgs> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::ICachedFileUpdaterUI)->add_FileUpdateRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::FileUpdateRequested_revoker consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::FileUpdateRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Storage::Provider::FileUpdateRequestedEventArgs> const& handler) const
{
    return impl::make_event_revoker<D, FileUpdateRequested_revoker>(this, FileUpdateRequested(handler));
}

template <typename D> void consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::FileUpdateRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Storage::Provider::ICachedFileUpdaterUI)->remove_FileUpdateRequested(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UIRequested(Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::ICachedFileUpdaterUI)->add_UIRequested(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UIRequested_revoker consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UIRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, UIRequested_revoker>(this, UIRequested(handler));
}

template <typename D> void consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UIRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Storage::Provider::ICachedFileUpdaterUI)->remove_UIRequested(get_abi(token)));
}

template <typename D> Windows::Storage::Provider::UIStatus consume_Windows_Storage_Provider_ICachedFileUpdaterUI<D>::UIStatus() const
{
    Windows::Storage::Provider::UIStatus value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::ICachedFileUpdaterUI)->get_UIStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Provider::FileUpdateRequest consume_Windows_Storage_Provider_ICachedFileUpdaterUI2<D>::UpdateRequest() const
{
    Windows::Storage::Provider::FileUpdateRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::ICachedFileUpdaterUI2)->get_UpdateRequest(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Provider::FileUpdateRequestDeferral consume_Windows_Storage_Provider_ICachedFileUpdaterUI2<D>::GetDeferral() const
{
    Windows::Storage::Provider::FileUpdateRequestDeferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::ICachedFileUpdaterUI2)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Storage_Provider_IFileUpdateRequest<D>::ContentId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IFileUpdateRequest)->get_ContentId(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::StorageFile consume_Windows_Storage_Provider_IFileUpdateRequest<D>::File() const
{
    Windows::Storage::StorageFile value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IFileUpdateRequest)->get_File(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Provider::FileUpdateStatus consume_Windows_Storage_Provider_IFileUpdateRequest<D>::Status() const
{
    Windows::Storage::Provider::FileUpdateStatus value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IFileUpdateRequest)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IFileUpdateRequest<D>::Status(Windows::Storage::Provider::FileUpdateStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IFileUpdateRequest)->put_Status(get_abi(value)));
}

template <typename D> Windows::Storage::Provider::FileUpdateRequestDeferral consume_Windows_Storage_Provider_IFileUpdateRequest<D>::GetDeferral() const
{
    Windows::Storage::Provider::FileUpdateRequestDeferral value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IFileUpdateRequest)->GetDeferral(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IFileUpdateRequest<D>::UpdateLocalFile(Windows::Storage::IStorageFile const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IFileUpdateRequest)->UpdateLocalFile(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Provider_IFileUpdateRequest2<D>::UserInputNeededMessage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IFileUpdateRequest2)->get_UserInputNeededMessage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IFileUpdateRequest2<D>::UserInputNeededMessage(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IFileUpdateRequest2)->put_UserInputNeededMessage(get_abi(value)));
}

template <typename D> void consume_Windows_Storage_Provider_IFileUpdateRequestDeferral<D>::Complete() const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IFileUpdateRequestDeferral)->Complete());
}

template <typename D> Windows::Storage::Provider::FileUpdateRequest consume_Windows_Storage_Provider_IFileUpdateRequestedEventArgs<D>::Request() const
{
    Windows::Storage::Provider::FileUpdateRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IFileUpdateRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Storage::Provider::StorageProviderUriSourceStatus consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::Status() const
{
    Windows::Storage::Provider::StorageProviderUriSourceStatus value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::Status(Windows::Storage::Provider::StorageProviderUriSourceStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->put_Status(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::ContentUri() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->get_ContentUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::ContentUri(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->put_ContentUri(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::ContentId() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->get_ContentId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderGetContentInfoForPathResult<D>::ContentId(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult)->put_ContentId(get_abi(value)));
}

template <typename D> Windows::Storage::Provider::StorageProviderUriSourceStatus consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult<D>::Status() const
{
    Windows::Storage::Provider::StorageProviderUriSourceStatus value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult<D>::Status(Windows::Storage::Provider::StorageProviderUriSourceStatus const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult)->put_Status(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult<D>::Path() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult)->get_Path(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderGetPathForContentUriResult<D>::Path(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult)->put_Path(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Storage_Provider_IStorageProviderItemPropertiesStatics<D>::SetAsync(Windows::Storage::IStorageItem const& item, param::async_iterable<Windows::Storage::Provider::StorageProviderItemProperty> const& itemProperties) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemPropertiesStatics)->SetAsync(get_abi(item), get_abi(itemProperties), put_abi(operation)));
    return operation;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::Id(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemProperty)->put_Id(value));
}

template <typename D> int32_t consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::Id() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemProperty)->get_Id(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::Value(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemProperty)->put_Value(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::Value() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemProperty)->get_Value(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::IconResource(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemProperty)->put_IconResource(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Provider_IStorageProviderItemProperty<D>::IconResource() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemProperty)->get_IconResource(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition<D>::Id() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemPropertyDefinition)->get_Id(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition<D>::Id(int32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemPropertyDefinition)->put_Id(value));
}

template <typename D> hstring consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition<D>::DisplayNameResource() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemPropertyDefinition)->get_DisplayNameResource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderItemPropertyDefinition<D>::DisplayNameResource(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemPropertyDefinition)->put_DisplayNameResource(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IIterable<Windows::Storage::Provider::StorageProviderItemProperty> consume_Windows_Storage_Provider_IStorageProviderItemPropertySource<D>::GetItemProperties(param::hstring const& itemPath) const
{
    Windows::Foundation::Collections::IIterable<Windows::Storage::Provider::StorageProviderItemProperty> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderItemPropertySource)->GetItemProperties(get_abi(itemPath), put_abi(result)));
    return result;
}

template <typename D> bool consume_Windows_Storage_Provider_IStorageProviderPropertyCapabilities<D>::IsPropertySupported(param::hstring const& propertyCanonicalName) const
{
    bool isSupported{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderPropertyCapabilities)->IsPropertySupported(get_abi(propertyCanonicalName), &isSupported));
    return isSupported;
}

template <typename D> hstring consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Id() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_Id(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Id(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_Id(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Context() const
{
    Windows::Storage::Streams::IBuffer value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_Context(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Context(Windows::Storage::Streams::IBuffer const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_Context(get_abi(value)));
}

template <typename D> Windows::Storage::IStorageFolder consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Path() const
{
    Windows::Storage::IStorageFolder value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_Path(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Path(Windows::Storage::IStorageFolder const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_Path(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::DisplayNameResource() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_DisplayNameResource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::DisplayNameResource(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_DisplayNameResource(get_abi(value)));
}

template <typename D> hstring consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::IconResource() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_IconResource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::IconResource(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_IconResource(get_abi(value)));
}

template <typename D> Windows::Storage::Provider::StorageProviderHydrationPolicy consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HydrationPolicy() const
{
    Windows::Storage::Provider::StorageProviderHydrationPolicy value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_HydrationPolicy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HydrationPolicy(Windows::Storage::Provider::StorageProviderHydrationPolicy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_HydrationPolicy(get_abi(value)));
}

template <typename D> Windows::Storage::Provider::StorageProviderHydrationPolicyModifier consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HydrationPolicyModifier() const
{
    Windows::Storage::Provider::StorageProviderHydrationPolicyModifier value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_HydrationPolicyModifier(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HydrationPolicyModifier(Windows::Storage::Provider::StorageProviderHydrationPolicyModifier const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_HydrationPolicyModifier(get_abi(value)));
}

template <typename D> Windows::Storage::Provider::StorageProviderPopulationPolicy consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::PopulationPolicy() const
{
    Windows::Storage::Provider::StorageProviderPopulationPolicy value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_PopulationPolicy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::PopulationPolicy(Windows::Storage::Provider::StorageProviderPopulationPolicy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_PopulationPolicy(get_abi(value)));
}

template <typename D> Windows::Storage::Provider::StorageProviderInSyncPolicy consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::InSyncPolicy() const
{
    Windows::Storage::Provider::StorageProviderInSyncPolicy value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_InSyncPolicy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::InSyncPolicy(Windows::Storage::Provider::StorageProviderInSyncPolicy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_InSyncPolicy(get_abi(value)));
}

template <typename D> Windows::Storage::Provider::StorageProviderHardlinkPolicy consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HardlinkPolicy() const
{
    Windows::Storage::Provider::StorageProviderHardlinkPolicy value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_HardlinkPolicy(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::HardlinkPolicy(Windows::Storage::Provider::StorageProviderHardlinkPolicy const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_HardlinkPolicy(get_abi(value)));
}

template <typename D> bool consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::ShowSiblingsAsGroup() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_ShowSiblingsAsGroup(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::ShowSiblingsAsGroup(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_ShowSiblingsAsGroup(value));
}

template <typename D> hstring consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Version() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_Version(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::Version(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_Version(get_abi(value)));
}

template <typename D> Windows::Storage::Provider::StorageProviderProtectionMode consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::ProtectionMode() const
{
    Windows::Storage::Provider::StorageProviderProtectionMode value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_ProtectionMode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::ProtectionMode(Windows::Storage::Provider::StorageProviderProtectionMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_ProtectionMode(get_abi(value)));
}

template <typename D> bool consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::AllowPinning() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_AllowPinning(&value));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::AllowPinning(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_AllowPinning(value));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Storage::Provider::StorageProviderItemPropertyDefinition> consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::StorageProviderItemPropertyDefinitions() const
{
    Windows::Foundation::Collections::IVector<Windows::Storage::Provider::StorageProviderItemPropertyDefinition> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_StorageProviderItemPropertyDefinitions(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Uri consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::RecycleBinUri() const
{
    Windows::Foundation::Uri value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->get_RecycleBinUri(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo<D>::RecycleBinUri(Windows::Foundation::Uri const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo)->put_RecycleBinUri(get_abi(value)));
}

template <typename D> winrt::guid consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo2<D>::ProviderId() const
{
    winrt::guid value{};
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo2)->get_ProviderId(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootInfo2<D>::ProviderId(winrt::guid const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootInfo2)->put_ProviderId(get_abi(value)));
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>::Register(Windows::Storage::Provider::StorageProviderSyncRootInfo const& syncRootInformation) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics)->Register(get_abi(syncRootInformation)));
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>::Unregister(param::hstring const& id) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics)->Unregister(get_abi(id)));
}

template <typename D> Windows::Storage::Provider::StorageProviderSyncRootInfo consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>::GetSyncRootInformationForFolder(Windows::Storage::IStorageFolder const& folder) const
{
    Windows::Storage::Provider::StorageProviderSyncRootInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics)->GetSyncRootInformationForFolder(get_abi(folder), put_abi(result)));
    return result;
}

template <typename D> Windows::Storage::Provider::StorageProviderSyncRootInfo consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>::GetSyncRootInformationForId(param::hstring const& id) const
{
    Windows::Storage::Provider::StorageProviderSyncRootInfo result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics)->GetSyncRootInformationForId(get_abi(id), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Storage::Provider::StorageProviderSyncRootInfo> consume_Windows_Storage_Provider_IStorageProviderSyncRootManagerStatics<D>::GetCurrentSyncRoots() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Storage::Provider::StorageProviderSyncRootInfo> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics)->GetCurrentSyncRoots(put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderUriSource<D>::GetPathForContentUri(param::hstring const& contentUri, Windows::Storage::Provider::StorageProviderGetPathForContentUriResult const& result) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderUriSource)->GetPathForContentUri(get_abi(contentUri), get_abi(result)));
}

template <typename D> void consume_Windows_Storage_Provider_IStorageProviderUriSource<D>::GetContentInfoForPath(param::hstring const& path, Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult const& result) const
{
    check_hresult(WINRT_SHIM(Windows::Storage::Provider::IStorageProviderUriSource)->GetContentInfoForPath(get_abi(path), get_abi(result)));
}

template <typename D>
struct produce<D, Windows::Storage::Provider::ICachedFileUpdaterStatics> : produce_base<D, Windows::Storage::Provider::ICachedFileUpdaterStatics>
{
    int32_t WINRT_CALL SetUpdateInformation(void* file, void* contentId, Windows::Storage::Provider::ReadActivationMode readMode, Windows::Storage::Provider::WriteActivationMode writeMode, Windows::Storage::Provider::CachedFileOptions options) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetUpdateInformation, WINRT_WRAP(void), Windows::Storage::IStorageFile const&, hstring const&, Windows::Storage::Provider::ReadActivationMode const&, Windows::Storage::Provider::WriteActivationMode const&, Windows::Storage::Provider::CachedFileOptions const&);
            this->shim().SetUpdateInformation(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<hstring const*>(&contentId), *reinterpret_cast<Windows::Storage::Provider::ReadActivationMode const*>(&readMode), *reinterpret_cast<Windows::Storage::Provider::WriteActivationMode const*>(&writeMode), *reinterpret_cast<Windows::Storage::Provider::CachedFileOptions const*>(&options));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::ICachedFileUpdaterUI> : produce_base<D, Windows::Storage::Provider::ICachedFileUpdaterUI>
{
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

    int32_t WINRT_CALL get_UpdateTarget(Windows::Storage::Provider::CachedFileTarget* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateTarget, WINRT_WRAP(Windows::Storage::Provider::CachedFileTarget));
            *value = detach_from<Windows::Storage::Provider::CachedFileTarget>(this->shim().UpdateTarget());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_FileUpdateRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FileUpdateRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Storage::Provider::FileUpdateRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().FileUpdateRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Storage::Provider::FileUpdateRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_FileUpdateRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(FileUpdateRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().FileUpdateRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_UIRequested(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UIRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().UIRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Storage::Provider::CachedFileUpdaterUI, Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_UIRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(UIRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().UIRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL get_UIStatus(Windows::Storage::Provider::UIStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UIStatus, WINRT_WRAP(Windows::Storage::Provider::UIStatus));
            *value = detach_from<Windows::Storage::Provider::UIStatus>(this->shim().UIStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::ICachedFileUpdaterUI2> : produce_base<D, Windows::Storage::Provider::ICachedFileUpdaterUI2>
{
    int32_t WINRT_CALL get_UpdateRequest(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateRequest, WINRT_WRAP(Windows::Storage::Provider::FileUpdateRequest));
            *value = detach_from<Windows::Storage::Provider::FileUpdateRequest>(this->shim().UpdateRequest());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Storage::Provider::FileUpdateRequestDeferral));
            *value = detach_from<Windows::Storage::Provider::FileUpdateRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IFileUpdateRequest> : produce_base<D, Windows::Storage::Provider::IFileUpdateRequest>
{
    int32_t WINRT_CALL get_ContentId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentId());
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
            WINRT_ASSERT_DECLARATION(File, WINRT_WRAP(Windows::Storage::StorageFile));
            *value = detach_from<Windows::Storage::StorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Status(Windows::Storage::Provider::FileUpdateStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Storage::Provider::FileUpdateStatus));
            *value = detach_from<Windows::Storage::Provider::FileUpdateStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Status(Windows::Storage::Provider::FileUpdateStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(void), Windows::Storage::Provider::FileUpdateStatus const&);
            this->shim().Status(*reinterpret_cast<Windows::Storage::Provider::FileUpdateStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetDeferral(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetDeferral, WINRT_WRAP(Windows::Storage::Provider::FileUpdateRequestDeferral));
            *value = detach_from<Windows::Storage::Provider::FileUpdateRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateLocalFile(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateLocalFile, WINRT_WRAP(void), Windows::Storage::IStorageFile const&);
            this->shim().UpdateLocalFile(*reinterpret_cast<Windows::Storage::IStorageFile const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IFileUpdateRequest2> : produce_base<D, Windows::Storage::Provider::IFileUpdateRequest2>
{
    int32_t WINRT_CALL get_UserInputNeededMessage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserInputNeededMessage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().UserInputNeededMessage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UserInputNeededMessage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UserInputNeededMessage, WINRT_WRAP(void), hstring const&);
            this->shim().UserInputNeededMessage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IFileUpdateRequestDeferral> : produce_base<D, Windows::Storage::Provider::IFileUpdateRequestDeferral>
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
struct produce<D, Windows::Storage::Provider::IFileUpdateRequestedEventArgs> : produce_base<D, Windows::Storage::Provider::IFileUpdateRequestedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Storage::Provider::FileUpdateRequest));
            *value = detach_from<Windows::Storage::Provider::FileUpdateRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult> : produce_base<D, Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult>
{
    int32_t WINRT_CALL get_Status(Windows::Storage::Provider::StorageProviderUriSourceStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Storage::Provider::StorageProviderUriSourceStatus));
            *value = detach_from<Windows::Storage::Provider::StorageProviderUriSourceStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Status(Windows::Storage::Provider::StorageProviderUriSourceStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(void), Windows::Storage::Provider::StorageProviderUriSourceStatus const&);
            this->shim().Status(*reinterpret_cast<Windows::Storage::Provider::StorageProviderUriSourceStatus const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentUri, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentUri, WINRT_WRAP(void), hstring const&);
            this->shim().ContentUri(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ContentId(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentId, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ContentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ContentId(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ContentId, WINRT_WRAP(void), hstring const&);
            this->shim().ContentId(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult> : produce_base<D, Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult>
{
    int32_t WINRT_CALL get_Status(Windows::Storage::Provider::StorageProviderUriSourceStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::Storage::Provider::StorageProviderUriSourceStatus));
            *value = detach_from<Windows::Storage::Provider::StorageProviderUriSourceStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Status(Windows::Storage::Provider::StorageProviderUriSourceStatus value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(void), Windows::Storage::Provider::StorageProviderUriSourceStatus const&);
            this->shim().Status(*reinterpret_cast<Windows::Storage::Provider::StorageProviderUriSourceStatus const*>(&value));
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

    int32_t WINRT_CALL put_Path(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(void), hstring const&);
            this->shim().Path(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IStorageProviderItemPropertiesStatics> : produce_base<D, Windows::Storage::Provider::IStorageProviderItemPropertiesStatics>
{
    int32_t WINRT_CALL SetAsync(void* item, void* itemProperties, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Storage::IStorageItem const, Windows::Foundation::Collections::IIterable<Windows::Storage::Provider::StorageProviderItemProperty> const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SetAsync(*reinterpret_cast<Windows::Storage::IStorageItem const*>(&item), *reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::Storage::Provider::StorageProviderItemProperty> const*>(&itemProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IStorageProviderItemProperty> : produce_base<D, Windows::Storage::Provider::IStorageProviderItemProperty>
{
    int32_t WINRT_CALL put_Id(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), int32_t);
            this->shim().Id(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Id(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), hstring const&);
            this->shim().Value(*reinterpret_cast<hstring const*>(&value));
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
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IconResource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconResource, WINRT_WRAP(void), hstring const&);
            this->shim().IconResource(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IconResource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconResource, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IconResource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IStorageProviderItemPropertyDefinition> : produce_base<D, Windows::Storage::Provider::IStorageProviderItemPropertyDefinition>
{
    int32_t WINRT_CALL get_Id(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Id(int32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), int32_t);
            this->shim().Id(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayNameResource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayNameResource, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayNameResource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayNameResource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayNameResource, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayNameResource(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IStorageProviderItemPropertySource> : produce_base<D, Windows::Storage::Provider::IStorageProviderItemPropertySource>
{
    int32_t WINRT_CALL GetItemProperties(void* itemPath, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetItemProperties, WINRT_WRAP(Windows::Foundation::Collections::IIterable<Windows::Storage::Provider::StorageProviderItemProperty>), hstring const&);
            *result = detach_from<Windows::Foundation::Collections::IIterable<Windows::Storage::Provider::StorageProviderItemProperty>>(this->shim().GetItemProperties(*reinterpret_cast<hstring const*>(&itemPath)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IStorageProviderPropertyCapabilities> : produce_base<D, Windows::Storage::Provider::IStorageProviderPropertyCapabilities>
{
    int32_t WINRT_CALL IsPropertySupported(void* propertyCanonicalName, bool* isSupported) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsPropertySupported, WINRT_WRAP(bool), hstring const&);
            *isSupported = detach_from<bool>(this->shim().IsPropertySupported(*reinterpret_cast<hstring const*>(&propertyCanonicalName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IStorageProviderSyncRootInfo> : produce_base<D, Windows::Storage::Provider::IStorageProviderSyncRootInfo>
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

    int32_t WINRT_CALL put_Id(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(void), hstring const&);
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Context(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Context, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *value = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().Context());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Context(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Context, WINRT_WRAP(void), Windows::Storage::Streams::IBuffer const&);
            this->shim().Context(*reinterpret_cast<Windows::Storage::Streams::IBuffer const*>(&value));
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
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(Windows::Storage::IStorageFolder));
            *value = detach_from<Windows::Storage::IStorageFolder>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Path(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(void), Windows::Storage::IStorageFolder const&);
            this->shim().Path(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_DisplayNameResource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayNameResource, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().DisplayNameResource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_DisplayNameResource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DisplayNameResource, WINRT_WRAP(void), hstring const&);
            this->shim().DisplayNameResource(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IconResource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconResource, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().IconResource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IconResource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IconResource, WINRT_WRAP(void), hstring const&);
            this->shim().IconResource(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HydrationPolicy(Windows::Storage::Provider::StorageProviderHydrationPolicy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HydrationPolicy, WINRT_WRAP(Windows::Storage::Provider::StorageProviderHydrationPolicy));
            *value = detach_from<Windows::Storage::Provider::StorageProviderHydrationPolicy>(this->shim().HydrationPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HydrationPolicy(Windows::Storage::Provider::StorageProviderHydrationPolicy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HydrationPolicy, WINRT_WRAP(void), Windows::Storage::Provider::StorageProviderHydrationPolicy const&);
            this->shim().HydrationPolicy(*reinterpret_cast<Windows::Storage::Provider::StorageProviderHydrationPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HydrationPolicyModifier(Windows::Storage::Provider::StorageProviderHydrationPolicyModifier* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HydrationPolicyModifier, WINRT_WRAP(Windows::Storage::Provider::StorageProviderHydrationPolicyModifier));
            *value = detach_from<Windows::Storage::Provider::StorageProviderHydrationPolicyModifier>(this->shim().HydrationPolicyModifier());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HydrationPolicyModifier(Windows::Storage::Provider::StorageProviderHydrationPolicyModifier value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HydrationPolicyModifier, WINRT_WRAP(void), Windows::Storage::Provider::StorageProviderHydrationPolicyModifier const&);
            this->shim().HydrationPolicyModifier(*reinterpret_cast<Windows::Storage::Provider::StorageProviderHydrationPolicyModifier const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PopulationPolicy(Windows::Storage::Provider::StorageProviderPopulationPolicy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PopulationPolicy, WINRT_WRAP(Windows::Storage::Provider::StorageProviderPopulationPolicy));
            *value = detach_from<Windows::Storage::Provider::StorageProviderPopulationPolicy>(this->shim().PopulationPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PopulationPolicy(Windows::Storage::Provider::StorageProviderPopulationPolicy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PopulationPolicy, WINRT_WRAP(void), Windows::Storage::Provider::StorageProviderPopulationPolicy const&);
            this->shim().PopulationPolicy(*reinterpret_cast<Windows::Storage::Provider::StorageProviderPopulationPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_InSyncPolicy(Windows::Storage::Provider::StorageProviderInSyncPolicy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InSyncPolicy, WINRT_WRAP(Windows::Storage::Provider::StorageProviderInSyncPolicy));
            *value = detach_from<Windows::Storage::Provider::StorageProviderInSyncPolicy>(this->shim().InSyncPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_InSyncPolicy(Windows::Storage::Provider::StorageProviderInSyncPolicy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(InSyncPolicy, WINRT_WRAP(void), Windows::Storage::Provider::StorageProviderInSyncPolicy const&);
            this->shim().InSyncPolicy(*reinterpret_cast<Windows::Storage::Provider::StorageProviderInSyncPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HardlinkPolicy(Windows::Storage::Provider::StorageProviderHardlinkPolicy* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardlinkPolicy, WINRT_WRAP(Windows::Storage::Provider::StorageProviderHardlinkPolicy));
            *value = detach_from<Windows::Storage::Provider::StorageProviderHardlinkPolicy>(this->shim().HardlinkPolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_HardlinkPolicy(Windows::Storage::Provider::StorageProviderHardlinkPolicy value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HardlinkPolicy, WINRT_WRAP(void), Windows::Storage::Provider::StorageProviderHardlinkPolicy const&);
            this->shim().HardlinkPolicy(*reinterpret_cast<Windows::Storage::Provider::StorageProviderHardlinkPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ShowSiblingsAsGroup(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowSiblingsAsGroup, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().ShowSiblingsAsGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ShowSiblingsAsGroup(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowSiblingsAsGroup, WINRT_WRAP(void), bool);
            this->shim().ShowSiblingsAsGroup(value);
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

    int32_t WINRT_CALL get_ProtectionMode(Windows::Storage::Provider::StorageProviderProtectionMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionMode, WINRT_WRAP(Windows::Storage::Provider::StorageProviderProtectionMode));
            *value = detach_from<Windows::Storage::Provider::StorageProviderProtectionMode>(this->shim().ProtectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProtectionMode(Windows::Storage::Provider::StorageProviderProtectionMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProtectionMode, WINRT_WRAP(void), Windows::Storage::Provider::StorageProviderProtectionMode const&);
            this->shim().ProtectionMode(*reinterpret_cast<Windows::Storage::Provider::StorageProviderProtectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_AllowPinning(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowPinning, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().AllowPinning());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_AllowPinning(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AllowPinning, WINRT_WRAP(void), bool);
            this->shim().AllowPinning(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_StorageProviderItemPropertyDefinitions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(StorageProviderItemPropertyDefinitions, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Storage::Provider::StorageProviderItemPropertyDefinition>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Storage::Provider::StorageProviderItemPropertyDefinition>>(this->shim().StorageProviderItemPropertyDefinitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RecycleBinUri(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecycleBinUri, WINRT_WRAP(Windows::Foundation::Uri));
            *value = detach_from<Windows::Foundation::Uri>(this->shim().RecycleBinUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RecycleBinUri(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecycleBinUri, WINRT_WRAP(void), Windows::Foundation::Uri const&);
            this->shim().RecycleBinUri(*reinterpret_cast<Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IStorageProviderSyncRootInfo2> : produce_base<D, Windows::Storage::Provider::IStorageProviderSyncRootInfo2>
{
    int32_t WINRT_CALL get_ProviderId(winrt::guid* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderId, WINRT_WRAP(winrt::guid));
            *value = detach_from<winrt::guid>(this->shim().ProviderId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ProviderId(winrt::guid value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ProviderId, WINRT_WRAP(void), winrt::guid const&);
            this->shim().ProviderId(*reinterpret_cast<winrt::guid const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics> : produce_base<D, Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>
{
    int32_t WINRT_CALL Register(void* syncRootInformation) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Register, WINRT_WRAP(void), Windows::Storage::Provider::StorageProviderSyncRootInfo const&);
            this->shim().Register(*reinterpret_cast<Windows::Storage::Provider::StorageProviderSyncRootInfo const*>(&syncRootInformation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Unregister(void* id) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unregister, WINRT_WRAP(void), hstring const&);
            this->shim().Unregister(*reinterpret_cast<hstring const*>(&id));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSyncRootInformationForFolder(void* folder, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSyncRootInformationForFolder, WINRT_WRAP(Windows::Storage::Provider::StorageProviderSyncRootInfo), Windows::Storage::IStorageFolder const&);
            *result = detach_from<Windows::Storage::Provider::StorageProviderSyncRootInfo>(this->shim().GetSyncRootInformationForFolder(*reinterpret_cast<Windows::Storage::IStorageFolder const*>(&folder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSyncRootInformationForId(void* id, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSyncRootInformationForId, WINRT_WRAP(Windows::Storage::Provider::StorageProviderSyncRootInfo), hstring const&);
            *result = detach_from<Windows::Storage::Provider::StorageProviderSyncRootInfo>(this->shim().GetSyncRootInformationForId(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetCurrentSyncRoots(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCurrentSyncRoots, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Storage::Provider::StorageProviderSyncRootInfo>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Storage::Provider::StorageProviderSyncRootInfo>>(this->shim().GetCurrentSyncRoots());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Storage::Provider::IStorageProviderUriSource> : produce_base<D, Windows::Storage::Provider::IStorageProviderUriSource>
{
    int32_t WINRT_CALL GetPathForContentUri(void* contentUri, void* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetPathForContentUri, WINRT_WRAP(void), hstring const&, Windows::Storage::Provider::StorageProviderGetPathForContentUriResult const&);
            this->shim().GetPathForContentUri(*reinterpret_cast<hstring const*>(&contentUri), *reinterpret_cast<Windows::Storage::Provider::StorageProviderGetPathForContentUriResult const*>(&result));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetContentInfoForPath(void* path, void* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetContentInfoForPath, WINRT_WRAP(void), hstring const&, Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult const&);
            this->shim().GetContentInfoForPath(*reinterpret_cast<hstring const*>(&path), *reinterpret_cast<Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult const*>(&result));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::Storage::Provider {

inline void CachedFileUpdater::SetUpdateInformation(Windows::Storage::IStorageFile const& file, param::hstring const& contentId, Windows::Storage::Provider::ReadActivationMode const& readMode, Windows::Storage::Provider::WriteActivationMode const& writeMode, Windows::Storage::Provider::CachedFileOptions const& options)
{
    impl::call_factory<CachedFileUpdater, Windows::Storage::Provider::ICachedFileUpdaterStatics>([&](auto&& f) { return f.SetUpdateInformation(file, contentId, readMode, writeMode, options); });
}

inline StorageProviderGetContentInfoForPathResult::StorageProviderGetContentInfoForPathResult() :
    StorageProviderGetContentInfoForPathResult(impl::call_factory<StorageProviderGetContentInfoForPathResult>([](auto&& f) { return f.template ActivateInstance<StorageProviderGetContentInfoForPathResult>(); }))
{}

inline StorageProviderGetPathForContentUriResult::StorageProviderGetPathForContentUriResult() :
    StorageProviderGetPathForContentUriResult(impl::call_factory<StorageProviderGetPathForContentUriResult>([](auto&& f) { return f.template ActivateInstance<StorageProviderGetPathForContentUriResult>(); }))
{}

inline Windows::Foundation::IAsyncAction StorageProviderItemProperties::SetAsync(Windows::Storage::IStorageItem const& item, param::async_iterable<Windows::Storage::Provider::StorageProviderItemProperty> const& itemProperties)
{
    return impl::call_factory<StorageProviderItemProperties, Windows::Storage::Provider::IStorageProviderItemPropertiesStatics>([&](auto&& f) { return f.SetAsync(item, itemProperties); });
}

inline StorageProviderItemProperty::StorageProviderItemProperty() :
    StorageProviderItemProperty(impl::call_factory<StorageProviderItemProperty>([](auto&& f) { return f.template ActivateInstance<StorageProviderItemProperty>(); }))
{}

inline StorageProviderItemPropertyDefinition::StorageProviderItemPropertyDefinition() :
    StorageProviderItemPropertyDefinition(impl::call_factory<StorageProviderItemPropertyDefinition>([](auto&& f) { return f.template ActivateInstance<StorageProviderItemPropertyDefinition>(); }))
{}

inline StorageProviderSyncRootInfo::StorageProviderSyncRootInfo() :
    StorageProviderSyncRootInfo(impl::call_factory<StorageProviderSyncRootInfo>([](auto&& f) { return f.template ActivateInstance<StorageProviderSyncRootInfo>(); }))
{}

inline void StorageProviderSyncRootManager::Register(Windows::Storage::Provider::StorageProviderSyncRootInfo const& syncRootInformation)
{
    impl::call_factory<StorageProviderSyncRootManager, Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>([&](auto&& f) { return f.Register(syncRootInformation); });
}

inline void StorageProviderSyncRootManager::Unregister(param::hstring const& id)
{
    impl::call_factory<StorageProviderSyncRootManager, Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>([&](auto&& f) { return f.Unregister(id); });
}

inline Windows::Storage::Provider::StorageProviderSyncRootInfo StorageProviderSyncRootManager::GetSyncRootInformationForFolder(Windows::Storage::IStorageFolder const& folder)
{
    return impl::call_factory<StorageProviderSyncRootManager, Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>([&](auto&& f) { return f.GetSyncRootInformationForFolder(folder); });
}

inline Windows::Storage::Provider::StorageProviderSyncRootInfo StorageProviderSyncRootManager::GetSyncRootInformationForId(param::hstring const& id)
{
    return impl::call_factory<StorageProviderSyncRootManager, Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>([&](auto&& f) { return f.GetSyncRootInformationForId(id); });
}

inline Windows::Foundation::Collections::IVectorView<Windows::Storage::Provider::StorageProviderSyncRootInfo> StorageProviderSyncRootManager::GetCurrentSyncRoots()
{
    return impl::call_factory<StorageProviderSyncRootManager, Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics>([&](auto&& f) { return f.GetCurrentSyncRoots(); });
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Storage::Provider::ICachedFileUpdaterStatics> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::ICachedFileUpdaterStatics> {};
template<> struct hash<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI> {};
template<> struct hash<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::ICachedFileUpdaterUI2> {};
template<> struct hash<winrt::Windows::Storage::Provider::IFileUpdateRequest> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IFileUpdateRequest> {};
template<> struct hash<winrt::Windows::Storage::Provider::IFileUpdateRequest2> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IFileUpdateRequest2> {};
template<> struct hash<winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IFileUpdateRequestDeferral> {};
template<> struct hash<winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IFileUpdateRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IStorageProviderGetContentInfoForPathResult> {};
template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IStorageProviderGetPathForContentUriResult> {};
template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderItemPropertiesStatics> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IStorageProviderItemPropertiesStatics> {};
template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderItemProperty> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IStorageProviderItemProperty> {};
template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IStorageProviderItemPropertyDefinition> {};
template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderItemPropertySource> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IStorageProviderItemPropertySource> {};
template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderPropertyCapabilities> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IStorageProviderPropertyCapabilities> {};
template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo> {};
template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IStorageProviderSyncRootInfo2> {};
template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IStorageProviderSyncRootManagerStatics> {};
template<> struct hash<winrt::Windows::Storage::Provider::IStorageProviderUriSource> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::IStorageProviderUriSource> {};
template<> struct hash<winrt::Windows::Storage::Provider::CachedFileUpdater> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::CachedFileUpdater> {};
template<> struct hash<winrt::Windows::Storage::Provider::CachedFileUpdaterUI> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::CachedFileUpdaterUI> {};
template<> struct hash<winrt::Windows::Storage::Provider::FileUpdateRequest> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::FileUpdateRequest> {};
template<> struct hash<winrt::Windows::Storage::Provider::FileUpdateRequestDeferral> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::FileUpdateRequestDeferral> {};
template<> struct hash<winrt::Windows::Storage::Provider::FileUpdateRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::FileUpdateRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::StorageProviderGetContentInfoForPathResult> {};
template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderGetPathForContentUriResult> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::StorageProviderGetPathForContentUriResult> {};
template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderItemProperties> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::StorageProviderItemProperties> {};
template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderItemProperty> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::StorageProviderItemProperty> {};
template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderItemPropertyDefinition> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::StorageProviderItemPropertyDefinition> {};
template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::StorageProviderSyncRootInfo> {};
template<> struct hash<winrt::Windows::Storage::Provider::StorageProviderSyncRootManager> : winrt::impl::hash_base<winrt::Windows::Storage::Provider::StorageProviderSyncRootManager> {};

}
