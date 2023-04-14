// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Graphics.Printing3D.2.h"
#include "winrt/Windows.Graphics.h"

namespace winrt::impl {

template <typename D> winrt::event_token consume_Windows_Graphics_Printing3D_IPrint3DManager<D>::TaskRequested(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DManager, Windows::Graphics::Printing3D::Print3DTaskRequestedEventArgs> const& eventHandler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DManager)->add_TaskRequested(get_abi(eventHandler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_Graphics_Printing3D_IPrint3DManager<D>::TaskRequested_revoker consume_Windows_Graphics_Printing3D_IPrint3DManager<D>::TaskRequested(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DManager, Windows::Graphics::Printing3D::Print3DTaskRequestedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, TaskRequested_revoker>(this, TaskRequested(eventHandler));
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrint3DManager<D>::TaskRequested(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DManager)->remove_TaskRequested(get_abi(token)));
}

template <typename D> Windows::Graphics::Printing3D::Print3DManager consume_Windows_Graphics_Printing3D_IPrint3DManagerStatics<D>::GetForCurrentView() const
{
    Windows::Graphics::Printing3D::Print3DManager result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DManagerStatics)->GetForCurrentView(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Graphics_Printing3D_IPrint3DManagerStatics<D>::ShowPrintUIAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DManagerStatics)->ShowPrintUIAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Printing3D::Printing3D3MFPackage consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::Source() const
{
    Windows::Graphics::Printing3D::Printing3D3MFPackage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTask)->get_Source(put_abi(value)));
    return value;
}

template <typename D> winrt::event_token consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::Submitting(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Foundation::IInspectable> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTask)->add_Submitting(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::Submitting_revoker consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::Submitting(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Foundation::IInspectable> const& eventHandler) const
{
    return impl::make_event_revoker<D, Submitting_revoker>(this, Submitting(eventHandler));
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::Submitting(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTask)->remove_Submitting(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::Completed(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Graphics::Printing3D::Print3DTaskCompletedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTask)->add_Completed(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::Completed_revoker consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::Completed(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Graphics::Printing3D::Print3DTaskCompletedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, Completed_revoker>(this, Completed(eventHandler));
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::Completed(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTask)->remove_Completed(get_abi(eventCookie)));
}

template <typename D> winrt::event_token consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::SourceChanged(Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Graphics::Printing3D::Print3DTaskSourceChangedEventArgs> const& eventHandler) const
{
    winrt::event_token eventCookie{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTask)->add_SourceChanged(get_abi(eventHandler), put_abi(eventCookie)));
    return eventCookie;
}

template <typename D> typename consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::SourceChanged_revoker consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::SourceChanged(auto_revoke_t, Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Graphics::Printing3D::Print3DTaskSourceChangedEventArgs> const& eventHandler) const
{
    return impl::make_event_revoker<D, SourceChanged_revoker>(this, SourceChanged(eventHandler));
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrint3DTask<D>::SourceChanged(winrt::event_token const& eventCookie) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTask)->remove_SourceChanged(get_abi(eventCookie)));
}

template <typename D> Windows::Graphics::Printing3D::Print3DTaskCompletion consume_Windows_Graphics_Printing3D_IPrint3DTaskCompletedEventArgs<D>::Completion() const
{
    Windows::Graphics::Printing3D::Print3DTaskCompletion value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTaskCompletedEventArgs)->get_Completion(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing3D::Print3DTaskDetail consume_Windows_Graphics_Printing3D_IPrint3DTaskCompletedEventArgs<D>::ExtendedStatus() const
{
    Windows::Graphics::Printing3D::Print3DTaskDetail value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTaskCompletedEventArgs)->get_ExtendedStatus(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing3D::Print3DTask consume_Windows_Graphics_Printing3D_IPrint3DTaskRequest<D>::CreateTask(param::hstring const& title, param::hstring const& printerId, Windows::Graphics::Printing3D::Print3DTaskSourceRequestedHandler const& handler) const
{
    Windows::Graphics::Printing3D::Print3DTask result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTaskRequest)->CreateTask(get_abi(title), get_abi(printerId), get_abi(handler), put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Printing3D::Print3DTaskRequest consume_Windows_Graphics_Printing3D_IPrint3DTaskRequestedEventArgs<D>::Request() const
{
    Windows::Graphics::Printing3D::Print3DTaskRequest value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTaskRequestedEventArgs)->get_Request(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing3D::Printing3D3MFPackage consume_Windows_Graphics_Printing3D_IPrint3DTaskSourceChangedEventArgs<D>::Source() const
{
    Windows::Graphics::Printing3D::Printing3D3MFPackage value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTaskSourceChangedEventArgs)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrint3DTaskSourceRequestedArgs<D>::SetSource(Windows::Graphics::Printing3D::Printing3D3MFPackage const& source) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrint3DTaskSourceRequestedArgs)->SetSource(get_abi(source)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage<D>::SaveAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage)->SaveAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage<D>::PrintTicket() const
{
    Windows::Storage::Streams::IRandomAccessStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage)->get_PrintTicket(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage<D>::PrintTicket(Windows::Storage::Streams::IRandomAccessStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage)->put_PrintTicket(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IRandomAccessStream consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage<D>::ModelPart() const
{
    Windows::Storage::Streams::IRandomAccessStream value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage)->get_ModelPart(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage<D>::ModelPart(Windows::Storage::Streams::IRandomAccessStream const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage)->put_ModelPart(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DTextureResource consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage<D>::Thumbnail() const
{
    Windows::Graphics::Printing3D::Printing3DTextureResource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage<D>::Thumbnail(Windows::Graphics::Printing3D::Printing3DTextureResource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage)->put_Thumbnail(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTextureResource> consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage<D>::Textures() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTextureResource> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage)->get_Textures(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3DModel> consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage<D>::LoadModelFromPackageAsync(Windows::Storage::Streams::IRandomAccessStream const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3DModel> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage)->LoadModelFromPackageAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage<D>::SaveModelToPackageAsync(Windows::Graphics::Printing3D::Printing3DModel const& value) const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage)->SaveModelToPackageAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DPackageCompression consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage2<D>::Compression() const
{
    Windows::Graphics::Printing3D::Printing3DPackageCompression value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage2)->get_Compression(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackage2<D>::Compression(Windows::Graphics::Printing3D::Printing3DPackageCompression const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackage2)->put_Compression(get_abi(value)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3D3MFPackage> consume_Windows_Graphics_Printing3D_IPrinting3D3MFPackageStatics<D>::LoadAsync(Windows::Storage::Streams::IRandomAccessStream const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3D3MFPackage> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3D3MFPackageStatics)->LoadAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> hstring consume_Windows_Graphics_Printing3D_IPrinting3DBaseMaterial<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DBaseMaterial)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DBaseMaterial<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DBaseMaterial)->put_Name(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DColorMaterial consume_Windows_Graphics_Printing3D_IPrinting3DBaseMaterial<D>::Color() const
{
    Windows::Graphics::Printing3D::Printing3DColorMaterial value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DBaseMaterial)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DBaseMaterial<D>::Color(Windows::Graphics::Printing3D::Printing3DColorMaterial const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DBaseMaterial)->put_Color(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DBaseMaterial> consume_Windows_Graphics_Printing3D_IPrinting3DBaseMaterialGroup<D>::Bases() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DBaseMaterial> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroup)->get_Bases(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Printing3D_IPrinting3DBaseMaterialGroup<D>::MaterialGroupId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroup)->get_MaterialGroupId(&value));
    return value;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup consume_Windows_Graphics_Printing3D_IPrinting3DBaseMaterialGroupFactory<D>::Create(uint32_t MaterialGroupId) const
{
    Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroupFactory)->Create(MaterialGroupId, put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_Graphics_Printing3D_IPrinting3DBaseMaterialStatics<D>::Abs() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DBaseMaterialStatics)->get_Abs(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_Graphics_Printing3D_IPrinting3DBaseMaterialStatics<D>::Pla() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DBaseMaterialStatics)->get_Pla(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Printing3D_IPrinting3DColorMaterial<D>::Value() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DColorMaterial)->get_Value(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DColorMaterial<D>::Value(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DColorMaterial)->put_Value(value));
}

template <typename D> Windows::UI::Color consume_Windows_Graphics_Printing3D_IPrinting3DColorMaterial2<D>::Color() const
{
    Windows::UI::Color value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DColorMaterial2)->get_Color(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DColorMaterial2<D>::Color(Windows::UI::Color const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DColorMaterial2)->put_Color(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DColorMaterial> consume_Windows_Graphics_Printing3D_IPrinting3DColorMaterialGroup<D>::Colors() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DColorMaterial> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroup)->get_Colors(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Printing3D_IPrinting3DColorMaterialGroup<D>::MaterialGroupId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroup)->get_MaterialGroupId(&value));
    return value;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DColorMaterialGroup consume_Windows_Graphics_Printing3D_IPrinting3DColorMaterialGroupFactory<D>::Create(uint32_t MaterialGroupId) const
{
    Windows::Graphics::Printing3D::Printing3DColorMaterialGroup result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroupFactory)->Create(MaterialGroupId, put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DMesh consume_Windows_Graphics_Printing3D_IPrinting3DComponent<D>::Mesh() const
{
    Windows::Graphics::Printing3D::Printing3DMesh value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponent)->get_Mesh(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DComponent<D>::Mesh(Windows::Graphics::Printing3D::Printing3DMesh const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponent)->put_Mesh(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DComponentWithMatrix> consume_Windows_Graphics_Printing3D_IPrinting3DComponent<D>::Components() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DComponentWithMatrix> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponent)->get_Components(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DTextureResource consume_Windows_Graphics_Printing3D_IPrinting3DComponent<D>::Thumbnail() const
{
    Windows::Graphics::Printing3D::Printing3DTextureResource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponent)->get_Thumbnail(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DComponent<D>::Thumbnail(Windows::Graphics::Printing3D::Printing3DTextureResource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponent)->put_Thumbnail(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DObjectType consume_Windows_Graphics_Printing3D_IPrinting3DComponent<D>::Type() const
{
    Windows::Graphics::Printing3D::Printing3DObjectType value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponent)->get_Type(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DComponent<D>::Type(Windows::Graphics::Printing3D::Printing3DObjectType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponent)->put_Type(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing3D_IPrinting3DComponent<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponent)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DComponent<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponent)->put_Name(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing3D_IPrinting3DComponent<D>::PartNumber() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponent)->get_PartNumber(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DComponent<D>::PartNumber(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponent)->put_PartNumber(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DComponent consume_Windows_Graphics_Printing3D_IPrinting3DComponentWithMatrix<D>::Component() const
{
    Windows::Graphics::Printing3D::Printing3DComponent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponentWithMatrix)->get_Component(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DComponentWithMatrix<D>::Component(Windows::Graphics::Printing3D::Printing3DComponent const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponentWithMatrix)->put_Component(get_abi(value)));
}

template <typename D> Windows::Foundation::Numerics::float4x4 consume_Windows_Graphics_Printing3D_IPrinting3DComponentWithMatrix<D>::Matrix() const
{
    Windows::Foundation::Numerics::float4x4 value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponentWithMatrix)->get_Matrix(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DComponentWithMatrix<D>::Matrix(Windows::Foundation::Numerics::float4x4 const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DComponentWithMatrix)->put_Matrix(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<double> consume_Windows_Graphics_Printing3D_IPrinting3DCompositeMaterial<D>::Values() const
{
    Windows::Foundation::Collections::IVector<double> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DCompositeMaterial)->get_Values(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DCompositeMaterial> consume_Windows_Graphics_Printing3D_IPrinting3DCompositeMaterialGroup<D>::Composites() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DCompositeMaterial> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup)->get_Composites(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Printing3D_IPrinting3DCompositeMaterialGroup<D>::MaterialGroupId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup)->get_MaterialGroupId(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<uint32_t> consume_Windows_Graphics_Printing3D_IPrinting3DCompositeMaterialGroup<D>::MaterialIndices() const
{
    Windows::Foundation::Collections::IVector<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup)->get_MaterialIndices(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup consume_Windows_Graphics_Printing3D_IPrinting3DCompositeMaterialGroup2<D>::BaseMaterialGroup() const
{
    Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup2)->get_BaseMaterialGroup(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DCompositeMaterialGroup2<D>::BaseMaterialGroup(Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup2)->put_BaseMaterialGroup(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DCompositeMaterialGroup consume_Windows_Graphics_Printing3D_IPrinting3DCompositeMaterialGroupFactory<D>::Create(uint32_t MaterialGroupId) const
{
    Windows::Graphics::Printing3D::Printing3DCompositeMaterialGroup result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroupFactory)->Create(MaterialGroupId, put_abi(result)));
    return result;
}

template <typename D> double consume_Windows_Graphics_Printing3D_IPrinting3DFaceReductionOptions<D>::MaxReductionArea() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DFaceReductionOptions)->get_MaxReductionArea(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DFaceReductionOptions<D>::MaxReductionArea(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DFaceReductionOptions)->put_MaxReductionArea(value));
}

template <typename D> uint32_t consume_Windows_Graphics_Printing3D_IPrinting3DFaceReductionOptions<D>::TargetTriangleCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DFaceReductionOptions)->get_TargetTriangleCount(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DFaceReductionOptions<D>::TargetTriangleCount(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DFaceReductionOptions)->put_TargetTriangleCount(value));
}

template <typename D> double consume_Windows_Graphics_Printing3D_IPrinting3DFaceReductionOptions<D>::MaxEdgeLength() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DFaceReductionOptions)->get_MaxEdgeLength(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DFaceReductionOptions<D>::MaxEdgeLength(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DFaceReductionOptions)->put_MaxEdgeLength(value));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup> consume_Windows_Graphics_Printing3D_IPrinting3DMaterial<D>::BaseGroups() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMaterial)->get_BaseGroups(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DColorMaterialGroup> consume_Windows_Graphics_Printing3D_IPrinting3DMaterial<D>::ColorGroups() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DColorMaterialGroup> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMaterial)->get_ColorGroups(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterialGroup> consume_Windows_Graphics_Printing3D_IPrinting3DMaterial<D>::Texture2CoordGroups() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterialGroup> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMaterial)->get_Texture2CoordGroups(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DCompositeMaterialGroup> consume_Windows_Graphics_Printing3D_IPrinting3DMaterial<D>::CompositeGroups() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DCompositeMaterialGroup> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMaterial)->get_CompositeGroups(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterialGroup> consume_Windows_Graphics_Printing3D_IPrinting3DMaterial<D>::MultiplePropertyGroups() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterialGroup> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMaterial)->get_MultiplePropertyGroups(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::VertexCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->get_VertexCount(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::VertexCount(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->put_VertexCount(value));
}

template <typename D> uint32_t consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::IndexCount() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->get_IndexCount(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::IndexCount(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->put_IndexCount(value));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DBufferDescription consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::VertexPositionsDescription() const
{
    Windows::Graphics::Printing3D::Printing3DBufferDescription value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->get_VertexPositionsDescription(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::VertexPositionsDescription(Windows::Graphics::Printing3D::Printing3DBufferDescription const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->put_VertexPositionsDescription(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DBufferDescription consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::VertexNormalsDescription() const
{
    Windows::Graphics::Printing3D::Printing3DBufferDescription value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->get_VertexNormalsDescription(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::VertexNormalsDescription(Windows::Graphics::Printing3D::Printing3DBufferDescription const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->put_VertexNormalsDescription(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DBufferDescription consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::TriangleIndicesDescription() const
{
    Windows::Graphics::Printing3D::Printing3DBufferDescription value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->get_TriangleIndicesDescription(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::TriangleIndicesDescription(Windows::Graphics::Printing3D::Printing3DBufferDescription const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->put_TriangleIndicesDescription(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DBufferDescription consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::TriangleMaterialIndicesDescription() const
{
    Windows::Graphics::Printing3D::Printing3DBufferDescription value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->get_TriangleMaterialIndicesDescription(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::TriangleMaterialIndicesDescription(Windows::Graphics::Printing3D::Printing3DBufferDescription const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->put_TriangleMaterialIndicesDescription(get_abi(value)));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::GetVertexPositions() const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->GetVertexPositions(put_abi(buffer)));
    return buffer;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::CreateVertexPositions(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->CreateVertexPositions(value));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::GetVertexNormals() const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->GetVertexNormals(put_abi(buffer)));
    return buffer;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::CreateVertexNormals(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->CreateVertexNormals(value));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::GetTriangleIndices() const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->GetTriangleIndices(put_abi(buffer)));
    return buffer;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::CreateTriangleIndices(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->CreateTriangleIndices(value));
}

template <typename D> Windows::Storage::Streams::IBuffer consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::GetTriangleMaterialIndices() const
{
    Windows::Storage::Streams::IBuffer buffer{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->GetTriangleMaterialIndices(put_abi(buffer)));
    return buffer;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::CreateTriangleMaterialIndices(uint32_t value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->CreateTriangleMaterialIndices(value));
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::BufferDescriptionSet() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->get_BufferDescriptionSet(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IPropertySet consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::BufferSet() const
{
    Windows::Foundation::Collections::IPropertySet value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->get_BufferSet(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3DMeshVerificationResult> consume_Windows_Graphics_Printing3D_IPrinting3DMesh<D>::VerifyAsync(Windows::Graphics::Printing3D::Printing3DMeshVerificationMode const& value) const
{
    Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3DMeshVerificationResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMesh)->VerifyAsync(get_abi(value), put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_Graphics_Printing3D_IPrinting3DMeshVerificationResult<D>::IsValid() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMeshVerificationResult)->get_IsValid(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Graphics_Printing3D_IPrinting3DMeshVerificationResult<D>::NonmanifoldTriangles() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMeshVerificationResult)->get_NonmanifoldTriangles(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_Graphics_Printing3D_IPrinting3DMeshVerificationResult<D>::ReversedNormalTriangles() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMeshVerificationResult)->get_ReversedNormalTriangles(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DModelUnit consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Unit() const
{
    Windows::Graphics::Printing3D::Printing3DModelUnit value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->get_Unit(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Unit(Windows::Graphics::Printing3D::Printing3DModelUnit const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->put_Unit(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DModelTexture> consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Textures() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DModelTexture> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->get_Textures(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMesh> consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Meshes() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMesh> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->get_Meshes(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DComponent> consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Components() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DComponent> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->get_Components(put_abi(value)));
    return value;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DMaterial consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Material() const
{
    Windows::Graphics::Printing3D::Printing3DMaterial value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->get_Material(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Material(Windows::Graphics::Printing3D::Printing3DMaterial const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->put_Material(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DComponent consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Build() const
{
    Windows::Graphics::Printing3D::Printing3DComponent value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->get_Build(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Build(Windows::Graphics::Printing3D::Printing3DComponent const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->put_Build(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Version() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->get_Version(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Version(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->put_Version(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<hstring> consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::RequiredExtensions() const
{
    Windows::Foundation::Collections::IVector<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->get_RequiredExtensions(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IMap<hstring, hstring> consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Metadata() const
{
    Windows::Foundation::Collections::IMap<hstring, hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->get_Metadata(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncAction consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::RepairAsync() const
{
    Windows::Foundation::IAsyncAction operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->RepairAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DModel consume_Windows_Graphics_Printing3D_IPrinting3DModel<D>::Clone() const
{
    Windows::Graphics::Printing3D::Printing3DModel value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel)->Clone(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Graphics_Printing3D_IPrinting3DModel2<D>::TryPartialRepairAsync() const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel2)->TryPartialRepairAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperation<bool> consume_Windows_Graphics_Printing3D_IPrinting3DModel2<D>::TryPartialRepairAsync(Windows::Foundation::TimeSpan const& maxWaitTime) const
{
    Windows::Foundation::IAsyncOperation<bool> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel2)->TryPartialRepairWithTimeAsync(get_abi(maxWaitTime), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<bool, double> consume_Windows_Graphics_Printing3D_IPrinting3DModel2<D>::TryReduceFacesAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<bool, double> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel2)->TryReduceFacesAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<bool, double> consume_Windows_Graphics_Printing3D_IPrinting3DModel2<D>::TryReduceFacesAsync(Windows::Graphics::Printing3D::Printing3DFaceReductionOptions const& printing3DFaceReductionOptions) const
{
    Windows::Foundation::IAsyncOperationWithProgress<bool, double> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel2)->TryReduceFacesWithOptionsAsync(get_abi(printing3DFaceReductionOptions), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<bool, double> consume_Windows_Graphics_Printing3D_IPrinting3DModel2<D>::TryReduceFacesAsync(Windows::Graphics::Printing3D::Printing3DFaceReductionOptions const& printing3DFaceReductionOptions, Windows::Foundation::TimeSpan const& maxWait) const
{
    Windows::Foundation::IAsyncOperationWithProgress<bool, double> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel2)->TryReduceFacesWithOptionsAndTimeAsync(get_abi(printing3DFaceReductionOptions), get_abi(maxWait), put_abi(operation)));
    return operation;
}

template <typename D> Windows::Foundation::IAsyncOperationWithProgress<bool, double> consume_Windows_Graphics_Printing3D_IPrinting3DModel2<D>::RepairWithProgressAsync() const
{
    Windows::Foundation::IAsyncOperationWithProgress<bool, double> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModel2)->RepairWithProgressAsync(put_abi(operation)));
    return operation;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DTextureResource consume_Windows_Graphics_Printing3D_IPrinting3DModelTexture<D>::TextureResource() const
{
    Windows::Graphics::Printing3D::Printing3DTextureResource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModelTexture)->get_TextureResource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DModelTexture<D>::TextureResource(Windows::Graphics::Printing3D::Printing3DTextureResource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModelTexture)->put_TextureResource(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior consume_Windows_Graphics_Printing3D_IPrinting3DModelTexture<D>::TileStyleU() const
{
    Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModelTexture)->get_TileStyleU(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DModelTexture<D>::TileStyleU(Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModelTexture)->put_TileStyleU(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior consume_Windows_Graphics_Printing3D_IPrinting3DModelTexture<D>::TileStyleV() const
{
    Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModelTexture)->get_TileStyleV(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DModelTexture<D>::TileStyleV(Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DModelTexture)->put_TileStyleV(get_abi(value)));
}

template <typename D> Windows::Foundation::Collections::IVector<uint32_t> consume_Windows_Graphics_Printing3D_IPrinting3DMultiplePropertyMaterial<D>::MaterialIndices() const
{
    Windows::Foundation::Collections::IVector<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterial)->get_MaterialIndices(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterial> consume_Windows_Graphics_Printing3D_IPrinting3DMultiplePropertyMaterialGroup<D>::MultipleProperties() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterial> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroup)->get_MultipleProperties(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVector<uint32_t> consume_Windows_Graphics_Printing3D_IPrinting3DMultiplePropertyMaterialGroup<D>::MaterialGroupIndices() const
{
    Windows::Foundation::Collections::IVector<uint32_t> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroup)->get_MaterialGroupIndices(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Printing3D_IPrinting3DMultiplePropertyMaterialGroup<D>::MaterialGroupId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroup)->get_MaterialGroupId(&value));
    return value;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterialGroup consume_Windows_Graphics_Printing3D_IPrinting3DMultiplePropertyMaterialGroupFactory<D>::Create(uint32_t MaterialGroupId) const
{
    Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterialGroup result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroupFactory)->Create(MaterialGroupId, put_abi(result)));
    return result;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DModelTexture consume_Windows_Graphics_Printing3D_IPrinting3DTexture2CoordMaterial<D>::Texture() const
{
    Windows::Graphics::Printing3D::Printing3DModelTexture value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterial)->get_Texture(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DTexture2CoordMaterial<D>::Texture(Windows::Graphics::Printing3D::Printing3DModelTexture const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterial)->put_Texture(get_abi(value)));
}

template <typename D> double consume_Windows_Graphics_Printing3D_IPrinting3DTexture2CoordMaterial<D>::U() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterial)->get_U(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DTexture2CoordMaterial<D>::U(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterial)->put_U(value));
}

template <typename D> double consume_Windows_Graphics_Printing3D_IPrinting3DTexture2CoordMaterial<D>::V() const
{
    double value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterial)->get_V(&value));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DTexture2CoordMaterial<D>::V(double value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterial)->put_V(value));
}

template <typename D> Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterial> consume_Windows_Graphics_Printing3D_IPrinting3DTexture2CoordMaterialGroup<D>::Texture2Coords() const
{
    Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterial> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup)->get_Texture2Coords(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_Graphics_Printing3D_IPrinting3DTexture2CoordMaterialGroup<D>::MaterialGroupId() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup)->get_MaterialGroupId(&value));
    return value;
}

template <typename D> Windows::Graphics::Printing3D::Printing3DModelTexture consume_Windows_Graphics_Printing3D_IPrinting3DTexture2CoordMaterialGroup2<D>::Texture() const
{
    Windows::Graphics::Printing3D::Printing3DModelTexture value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup2)->get_Texture(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DTexture2CoordMaterialGroup2<D>::Texture(Windows::Graphics::Printing3D::Printing3DModelTexture const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup2)->put_Texture(get_abi(value)));
}

template <typename D> Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterialGroup consume_Windows_Graphics_Printing3D_IPrinting3DTexture2CoordMaterialGroupFactory<D>::Create(uint32_t MaterialGroupId) const
{
    Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterialGroup result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroupFactory)->Create(MaterialGroupId, put_abi(result)));
    return result;
}

template <typename D> Windows::Storage::Streams::IRandomAccessStreamWithContentType consume_Windows_Graphics_Printing3D_IPrinting3DTextureResource<D>::TextureData() const
{
    Windows::Storage::Streams::IRandomAccessStreamWithContentType value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTextureResource)->get_TextureData(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DTextureResource<D>::TextureData(Windows::Storage::Streams::IRandomAccessStreamWithContentType const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTextureResource)->put_TextureData(get_abi(value)));
}

template <typename D> hstring consume_Windows_Graphics_Printing3D_IPrinting3DTextureResource<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTextureResource)->get_Name(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_Graphics_Printing3D_IPrinting3DTextureResource<D>::Name(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::Graphics::Printing3D::IPrinting3DTextureResource)->put_Name(get_abi(value)));
}

template <> struct delegate<Windows::Graphics::Printing3D::Print3DTaskSourceRequestedHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::Graphics::Printing3D::Print3DTaskSourceRequestedHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::Graphics::Printing3D::Print3DTaskSourceRequestedHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* args) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Graphics::Printing3D::Print3DTaskSourceRequestedArgs const*>(&args));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrint3DManager> : produce_base<D, Windows::Graphics::Printing3D::IPrint3DManager>
{
    int32_t WINRT_CALL add_TaskRequested(void* eventHandler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TaskRequested, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DManager, Windows::Graphics::Printing3D::Print3DTaskRequestedEventArgs> const&);
            *token = detach_from<winrt::event_token>(this->shim().TaskRequested(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DManager, Windows::Graphics::Printing3D::Print3DTaskRequestedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_TaskRequested(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(TaskRequested, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().TaskRequested(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrint3DManagerStatics> : produce_base<D, Windows::Graphics::Printing3D::IPrint3DManagerStatics>
{
    int32_t WINRT_CALL GetForCurrentView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetForCurrentView, WINRT_WRAP(Windows::Graphics::Printing3D::Print3DManager));
            *result = detach_from<Windows::Graphics::Printing3D::Print3DManager>(this->shim().GetForCurrentView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ShowPrintUIAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ShowPrintUIAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().ShowPrintUIAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrint3DTask> : produce_base<D, Windows::Graphics::Printing3D::IPrint3DTask>
{
    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3D3MFPackage));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3D3MFPackage>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_Submitting(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Submitting, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Foundation::IInspectable> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().Submitting(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Foundation::IInspectable> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Submitting(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Submitting, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Submitting(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL add_Completed(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Graphics::Printing3D::Print3DTaskCompletedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().Completed(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Graphics::Printing3D::Print3DTaskCompletedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_Completed(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(Completed, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().Completed(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }

    int32_t WINRT_CALL add_SourceChanged(void* eventHandler, winrt::event_token* eventCookie) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Graphics::Printing3D::Print3DTaskSourceChangedEventArgs> const&);
            *eventCookie = detach_from<winrt::event_token>(this->shim().SourceChanged(*reinterpret_cast<Windows::Foundation::TypedEventHandler<Windows::Graphics::Printing3D::Print3DTask, Windows::Graphics::Printing3D::Print3DTaskSourceChangedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_SourceChanged(winrt::event_token eventCookie) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(SourceChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().SourceChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrint3DTaskCompletedEventArgs> : produce_base<D, Windows::Graphics::Printing3D::IPrint3DTaskCompletedEventArgs>
{
    int32_t WINRT_CALL get_Completion(Windows::Graphics::Printing3D::Print3DTaskCompletion* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Completion, WINRT_WRAP(Windows::Graphics::Printing3D::Print3DTaskCompletion));
            *value = detach_from<Windows::Graphics::Printing3D::Print3DTaskCompletion>(this->shim().Completion());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ExtendedStatus(Windows::Graphics::Printing3D::Print3DTaskDetail* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ExtendedStatus, WINRT_WRAP(Windows::Graphics::Printing3D::Print3DTaskDetail));
            *value = detach_from<Windows::Graphics::Printing3D::Print3DTaskDetail>(this->shim().ExtendedStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrint3DTaskRequest> : produce_base<D, Windows::Graphics::Printing3D::IPrint3DTaskRequest>
{
    int32_t WINRT_CALL CreateTask(void* title, void* printerId, void* handler, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTask, WINRT_WRAP(Windows::Graphics::Printing3D::Print3DTask), hstring const&, hstring const&, Windows::Graphics::Printing3D::Print3DTaskSourceRequestedHandler const&);
            *result = detach_from<Windows::Graphics::Printing3D::Print3DTask>(this->shim().CreateTask(*reinterpret_cast<hstring const*>(&title), *reinterpret_cast<hstring const*>(&printerId), *reinterpret_cast<Windows::Graphics::Printing3D::Print3DTaskSourceRequestedHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrint3DTaskRequestedEventArgs> : produce_base<D, Windows::Graphics::Printing3D::IPrint3DTaskRequestedEventArgs>
{
    int32_t WINRT_CALL get_Request(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Request, WINRT_WRAP(Windows::Graphics::Printing3D::Print3DTaskRequest));
            *value = detach_from<Windows::Graphics::Printing3D::Print3DTaskRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrint3DTaskSourceChangedEventArgs> : produce_base<D, Windows::Graphics::Printing3D::IPrint3DTaskSourceChangedEventArgs>
{
    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3D3MFPackage));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3D3MFPackage>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrint3DTaskSourceRequestedArgs> : produce_base<D, Windows::Graphics::Printing3D::IPrint3DTaskSourceRequestedArgs>
{
    int32_t WINRT_CALL SetSource(void* source) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetSource, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3D3MFPackage const&);
            this->shim().SetSource(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3D3MFPackage const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3D3MFPackage> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3D3MFPackage>
{
    int32_t WINRT_CALL SaveAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Storage::Streams::IRandomAccessStream>>(this->shim().SaveAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_PrintTicket(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintTicket, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStream));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStream>(this->shim().PrintTicket());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PrintTicket(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PrintTicket, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStream const&);
            this->shim().PrintTicket(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ModelPart(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelPart, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStream));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStream>(this->shim().ModelPart());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ModelPart(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ModelPart, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStream const&);
            this->shim().ModelPart(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DTextureResource));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DTextureResource>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Thumbnail(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DTextureResource const&);
            this->shim().Thumbnail(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DTextureResource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Textures(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Textures, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTextureResource>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTextureResource>>(this->shim().Textures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadModelFromPackageAsync(void* value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadModelFromPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3DModel>), Windows::Storage::Streams::IRandomAccessStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3DModel>>(this->shim().LoadModelFromPackageAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SaveModelToPackageAsync(void* value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SaveModelToPackageAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction), Windows::Graphics::Printing3D::Printing3DModel const);
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().SaveModelToPackageAsync(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DModel const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3D3MFPackage2> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3D3MFPackage2>
{
    int32_t WINRT_CALL get_Compression(Windows::Graphics::Printing3D::Printing3DPackageCompression* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compression, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DPackageCompression));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DPackageCompression>(this->shim().Compression());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Compression(Windows::Graphics::Printing3D::Printing3DPackageCompression value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Compression, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DPackageCompression const&);
            this->shim().Compression(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DPackageCompression const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3D3MFPackageStatics> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3D3MFPackageStatics>
{
    int32_t WINRT_CALL LoadAsync(void* value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3D3MFPackage>), Windows::Storage::Streams::IRandomAccessStream const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3D3MFPackage>>(this->shim().LoadAsync(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStream const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DBaseMaterial> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DBaseMaterial>
{
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

    int32_t WINRT_CALL get_Color(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DColorMaterial));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DColorMaterial>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DColorMaterial const&);
            this->shim().Color(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DColorMaterial const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroup> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroup>
{
    int32_t WINRT_CALL get_Bases(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Bases, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DBaseMaterial>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DBaseMaterial>>(this->shim().Bases());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaterialGroupId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaterialGroupId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaterialGroupId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroupFactory> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroupFactory>
{
    int32_t WINRT_CALL Create(uint32_t MaterialGroupId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup), uint32_t);
            *result = detach_from<Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup>(this->shim().Create(MaterialGroupId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DBaseMaterialStatics> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DBaseMaterialStatics>
{
    int32_t WINRT_CALL get_Abs(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Abs, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Abs());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Pla(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Pla, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().Pla());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DColorMaterial> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DColorMaterial>
{
    int32_t WINRT_CALL get_Value(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Value(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Value, WINRT_WRAP(void), uint32_t);
            this->shim().Value(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DColorMaterial2> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DColorMaterial2>
{
    int32_t WINRT_CALL get_Color(struct struct_Windows_UI_Color* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(Windows::UI::Color));
            *value = detach_from<Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Color(struct struct_Windows_UI_Color value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Color, WINRT_WRAP(void), Windows::UI::Color const&);
            this->shim().Color(*reinterpret_cast<Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroup> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroup>
{
    int32_t WINRT_CALL get_Colors(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Colors, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DColorMaterial>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DColorMaterial>>(this->shim().Colors());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaterialGroupId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaterialGroupId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaterialGroupId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroupFactory> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroupFactory>
{
    int32_t WINRT_CALL Create(uint32_t MaterialGroupId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DColorMaterialGroup), uint32_t);
            *result = detach_from<Windows::Graphics::Printing3D::Printing3DColorMaterialGroup>(this->shim().Create(MaterialGroupId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DComponent> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DComponent>
{
    int32_t WINRT_CALL get_Mesh(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mesh, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DMesh));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DMesh>(this->shim().Mesh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mesh(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mesh, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DMesh const&);
            this->shim().Mesh(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DMesh const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Components(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Components, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DComponentWithMatrix>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DComponentWithMatrix>>(this->shim().Components());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Thumbnail(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DTextureResource));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DTextureResource>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Thumbnail(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Thumbnail, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DTextureResource const&);
            this->shim().Thumbnail(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DTextureResource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(Windows::Graphics::Printing3D::Printing3DObjectType* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DObjectType));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DObjectType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Type(Windows::Graphics::Printing3D::Printing3DObjectType value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DObjectType const&);
            this->shim().Type(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DObjectType const*>(&value));
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

    int32_t WINRT_CALL get_PartNumber(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PartNumber, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PartNumber());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_PartNumber(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PartNumber, WINRT_WRAP(void), hstring const&);
            this->shim().PartNumber(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DComponentWithMatrix> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DComponentWithMatrix>
{
    int32_t WINRT_CALL get_Component(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Component, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DComponent));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DComponent>(this->shim().Component());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Component(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Component, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DComponent const&);
            this->shim().Component(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DComponent const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Matrix(Windows::Foundation::Numerics::float4x4* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Matrix, WINRT_WRAP(Windows::Foundation::Numerics::float4x4));
            *value = detach_from<Windows::Foundation::Numerics::float4x4>(this->shim().Matrix());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Matrix(Windows::Foundation::Numerics::float4x4 value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Matrix, WINRT_WRAP(void), Windows::Foundation::Numerics::float4x4 const&);
            this->shim().Matrix(*reinterpret_cast<Windows::Foundation::Numerics::float4x4 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DCompositeMaterial> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DCompositeMaterial>
{
    int32_t WINRT_CALL get_Values(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Values, WINRT_WRAP(Windows::Foundation::Collections::IVector<double>));
            *value = detach_from<Windows::Foundation::Collections::IVector<double>>(this->shim().Values());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup>
{
    int32_t WINRT_CALL get_Composites(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Composites, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DCompositeMaterial>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DCompositeMaterial>>(this->shim().Composites());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaterialGroupId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaterialGroupId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaterialGroupId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaterialIndices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaterialIndices, WINRT_WRAP(Windows::Foundation::Collections::IVector<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVector<uint32_t>>(this->shim().MaterialIndices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup2> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup2>
{
    int32_t WINRT_CALL get_BaseMaterialGroup(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseMaterialGroup, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup>(this->shim().BaseMaterialGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_BaseMaterialGroup(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseMaterialGroup, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup const&);
            this->shim().BaseMaterialGroup(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroupFactory> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroupFactory>
{
    int32_t WINRT_CALL Create(uint32_t MaterialGroupId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DCompositeMaterialGroup), uint32_t);
            *result = detach_from<Windows::Graphics::Printing3D::Printing3DCompositeMaterialGroup>(this->shim().Create(MaterialGroupId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DFaceReductionOptions> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DFaceReductionOptions>
{
    int32_t WINRT_CALL get_MaxReductionArea(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxReductionArea, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MaxReductionArea());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxReductionArea(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxReductionArea, WINRT_WRAP(void), double);
            this->shim().MaxReductionArea(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetTriangleCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetTriangleCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().TargetTriangleCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetTriangleCount(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetTriangleCount, WINRT_WRAP(void), uint32_t);
            this->shim().TargetTriangleCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaxEdgeLength(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxEdgeLength, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().MaxEdgeLength());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_MaxEdgeLength(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaxEdgeLength, WINRT_WRAP(void), double);
            this->shim().MaxEdgeLength(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DMaterial> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DMaterial>
{
    int32_t WINRT_CALL get_BaseGroups(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BaseGroups, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup>>(this->shim().BaseGroups());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ColorGroups(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ColorGroups, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DColorMaterialGroup>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DColorMaterialGroup>>(this->shim().ColorGroups());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Texture2CoordGroups(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Texture2CoordGroups, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterialGroup>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterialGroup>>(this->shim().Texture2CoordGroups());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CompositeGroups(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CompositeGroups, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DCompositeMaterialGroup>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DCompositeMaterialGroup>>(this->shim().CompositeGroups());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MultiplePropertyGroups(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MultiplePropertyGroups, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterialGroup>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterialGroup>>(this->shim().MultiplePropertyGroups());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DMesh> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DMesh>
{
    int32_t WINRT_CALL get_VertexCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VertexCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().VertexCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VertexCount(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VertexCount, WINRT_WRAP(void), uint32_t);
            this->shim().VertexCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IndexCount(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndexCount, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().IndexCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IndexCount(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndexCount, WINRT_WRAP(void), uint32_t);
            this->shim().IndexCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VertexPositionsDescription(struct struct_Windows_Graphics_Printing3D_Printing3DBufferDescription* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VertexPositionsDescription, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DBufferDescription));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DBufferDescription>(this->shim().VertexPositionsDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VertexPositionsDescription(struct struct_Windows_Graphics_Printing3D_Printing3DBufferDescription value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VertexPositionsDescription, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DBufferDescription const&);
            this->shim().VertexPositionsDescription(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DBufferDescription const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_VertexNormalsDescription(struct struct_Windows_Graphics_Printing3D_Printing3DBufferDescription* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VertexNormalsDescription, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DBufferDescription));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DBufferDescription>(this->shim().VertexNormalsDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_VertexNormalsDescription(struct struct_Windows_Graphics_Printing3D_Printing3DBufferDescription value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VertexNormalsDescription, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DBufferDescription const&);
            this->shim().VertexNormalsDescription(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DBufferDescription const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TriangleIndicesDescription(struct struct_Windows_Graphics_Printing3D_Printing3DBufferDescription* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriangleIndicesDescription, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DBufferDescription));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DBufferDescription>(this->shim().TriangleIndicesDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TriangleIndicesDescription(struct struct_Windows_Graphics_Printing3D_Printing3DBufferDescription value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriangleIndicesDescription, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DBufferDescription const&);
            this->shim().TriangleIndicesDescription(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DBufferDescription const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TriangleMaterialIndicesDescription(struct struct_Windows_Graphics_Printing3D_Printing3DBufferDescription* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriangleMaterialIndicesDescription, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DBufferDescription));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DBufferDescription>(this->shim().TriangleMaterialIndicesDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TriangleMaterialIndicesDescription(struct struct_Windows_Graphics_Printing3D_Printing3DBufferDescription value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TriangleMaterialIndicesDescription, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DBufferDescription const&);
            this->shim().TriangleMaterialIndicesDescription(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DBufferDescription const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVertexPositions(void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVertexPositions, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().GetVertexPositions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateVertexPositions(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateVertexPositions, WINRT_WRAP(void), uint32_t);
            this->shim().CreateVertexPositions(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetVertexNormals(void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetVertexNormals, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().GetVertexNormals());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateVertexNormals(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateVertexNormals, WINRT_WRAP(void), uint32_t);
            this->shim().CreateVertexNormals(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTriangleIndices(void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTriangleIndices, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().GetTriangleIndices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTriangleIndices(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTriangleIndices, WINRT_WRAP(void), uint32_t);
            this->shim().CreateTriangleIndices(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetTriangleMaterialIndices(void** buffer) noexcept final
    {
        try
        {
            *buffer = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetTriangleMaterialIndices, WINRT_WRAP(Windows::Storage::Streams::IBuffer));
            *buffer = detach_from<Windows::Storage::Streams::IBuffer>(this->shim().GetTriangleMaterialIndices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateTriangleMaterialIndices(uint32_t value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateTriangleMaterialIndices, WINRT_WRAP(void), uint32_t);
            this->shim().CreateTriangleMaterialIndices(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BufferDescriptionSet(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferDescriptionSet, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().BufferDescriptionSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BufferSet(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BufferSet, WINRT_WRAP(Windows::Foundation::Collections::IPropertySet));
            *value = detach_from<Windows::Foundation::Collections::IPropertySet>(this->shim().BufferSet());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL VerifyAsync(Windows::Graphics::Printing3D::Printing3DMeshVerificationMode value, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(VerifyAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3DMeshVerificationResult>), Windows::Graphics::Printing3D::Printing3DMeshVerificationMode const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3DMeshVerificationResult>>(this->shim().VerifyAsync(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DMeshVerificationMode const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DMeshVerificationResult> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DMeshVerificationResult>
{
    int32_t WINRT_CALL get_IsValid(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsValid, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsValid());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_NonmanifoldTriangles(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(NonmanifoldTriangles, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().NonmanifoldTriangles());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ReversedNormalTriangles(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReversedNormalTriangles, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().ReversedNormalTriangles());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DModel> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DModel>
{
    int32_t WINRT_CALL get_Unit(Windows::Graphics::Printing3D::Printing3DModelUnit* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unit, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DModelUnit));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DModelUnit>(this->shim().Unit());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Unit(Windows::Graphics::Printing3D::Printing3DModelUnit value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Unit, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DModelUnit const&);
            this->shim().Unit(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DModelUnit const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Textures(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Textures, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DModelTexture>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DModelTexture>>(this->shim().Textures());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Meshes(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Meshes, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMesh>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMesh>>(this->shim().Meshes());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Components(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Components, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DComponent>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DComponent>>(this->shim().Components());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Material(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Material, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DMaterial));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DMaterial>(this->shim().Material());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Material(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Material, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DMaterial const&);
            this->shim().Material(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DMaterial const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Build(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Build, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DComponent));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DComponent>(this->shim().Build());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Build(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Build, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DComponent const&);
            this->shim().Build(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DComponent const*>(&value));
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

    int32_t WINRT_CALL get_RequiredExtensions(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RequiredExtensions, WINRT_WRAP(Windows::Foundation::Collections::IVector<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVector<hstring>>(this->shim().RequiredExtensions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Metadata(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Metadata, WINRT_WRAP(Windows::Foundation::Collections::IMap<hstring, hstring>));
            *value = detach_from<Windows::Foundation::Collections::IMap<hstring, hstring>>(this->shim().Metadata());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RepairAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepairAsync, WINRT_WRAP(Windows::Foundation::IAsyncAction));
            *operation = detach_from<Windows::Foundation::IAsyncAction>(this->shim().RepairAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL Clone(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Clone, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DModel));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DModel>(this->shim().Clone());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DModel2> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DModel2>
{
    int32_t WINRT_CALL TryPartialRepairAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryPartialRepairAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>));
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryPartialRepairAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryPartialRepairWithTimeAsync(Windows::Foundation::TimeSpan maxWaitTime, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryPartialRepairAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<bool>), Windows::Foundation::TimeSpan const);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<bool>>(this->shim().TryPartialRepairAsync(*reinterpret_cast<Windows::Foundation::TimeSpan const*>(&maxWaitTime)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryReduceFacesAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryReduceFacesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<bool, double>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<bool, double>>(this->shim().TryReduceFacesAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryReduceFacesWithOptionsAsync(void* printing3DFaceReductionOptions, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryReduceFacesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<bool, double>), Windows::Graphics::Printing3D::Printing3DFaceReductionOptions const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<bool, double>>(this->shim().TryReduceFacesAsync(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DFaceReductionOptions const*>(&printing3DFaceReductionOptions)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL TryReduceFacesWithOptionsAndTimeAsync(void* printing3DFaceReductionOptions, Windows::Foundation::TimeSpan maxWait, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TryReduceFacesAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<bool, double>), Windows::Graphics::Printing3D::Printing3DFaceReductionOptions const, Windows::Foundation::TimeSpan const);
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<bool, double>>(this->shim().TryReduceFacesAsync(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DFaceReductionOptions const*>(&printing3DFaceReductionOptions), *reinterpret_cast<Windows::Foundation::TimeSpan const*>(&maxWait)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RepairWithProgressAsync(void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RepairWithProgressAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperationWithProgress<bool, double>));
            *operation = detach_from<Windows::Foundation::IAsyncOperationWithProgress<bool, double>>(this->shim().RepairWithProgressAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DModelTexture> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DModelTexture>
{
    int32_t WINRT_CALL get_TextureResource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextureResource, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DTextureResource));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DTextureResource>(this->shim().TextureResource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TextureResource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextureResource, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DTextureResource const&);
            this->shim().TextureResource(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DTextureResource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TileStyleU(Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TileStyleU, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior>(this->shim().TileStyleU());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TileStyleU(Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TileStyleU, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior const&);
            this->shim().TileStyleU(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TileStyleV(Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TileStyleV, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior>(this->shim().TileStyleV());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TileStyleV(Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TileStyleV, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior const&);
            this->shim().TileStyleV(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DTextureEdgeBehavior const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterial> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterial>
{
    int32_t WINRT_CALL get_MaterialIndices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaterialIndices, WINRT_WRAP(Windows::Foundation::Collections::IVector<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVector<uint32_t>>(this->shim().MaterialIndices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroup> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroup>
{
    int32_t WINRT_CALL get_MultipleProperties(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MultipleProperties, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterial>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterial>>(this->shim().MultipleProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaterialGroupIndices(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaterialGroupIndices, WINRT_WRAP(Windows::Foundation::Collections::IVector<uint32_t>));
            *value = detach_from<Windows::Foundation::Collections::IVector<uint32_t>>(this->shim().MaterialGroupIndices());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaterialGroupId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaterialGroupId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaterialGroupId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroupFactory> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroupFactory>
{
    int32_t WINRT_CALL Create(uint32_t MaterialGroupId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterialGroup), uint32_t);
            *result = detach_from<Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterialGroup>(this->shim().Create(MaterialGroupId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterial> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterial>
{
    int32_t WINRT_CALL get_Texture(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Texture, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DModelTexture));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DModelTexture>(this->shim().Texture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Texture(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Texture, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DModelTexture const&);
            this->shim().Texture(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DModelTexture const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_U(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(U, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().U());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_U(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(U, WINRT_WRAP(void), double);
            this->shim().U(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_V(double* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(V, WINRT_WRAP(double));
            *value = detach_from<double>(this->shim().V());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_V(double value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(V, WINRT_WRAP(void), double);
            this->shim().V(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup>
{
    int32_t WINRT_CALL get_Texture2Coords(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Texture2Coords, WINRT_WRAP(Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterial>));
            *value = detach_from<Windows::Foundation::Collections::IVector<Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterial>>(this->shim().Texture2Coords());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_MaterialGroupId(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MaterialGroupId, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().MaterialGroupId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup2> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup2>
{
    int32_t WINRT_CALL get_Texture(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Texture, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DModelTexture));
            *value = detach_from<Windows::Graphics::Printing3D::Printing3DModelTexture>(this->shim().Texture());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Texture(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Texture, WINRT_WRAP(void), Windows::Graphics::Printing3D::Printing3DModelTexture const&);
            this->shim().Texture(*reinterpret_cast<Windows::Graphics::Printing3D::Printing3DModelTexture const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroupFactory> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroupFactory>
{
    int32_t WINRT_CALL Create(uint32_t MaterialGroupId, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Create, WINRT_WRAP(Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterialGroup), uint32_t);
            *result = detach_from<Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterialGroup>(this->shim().Create(MaterialGroupId));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::Graphics::Printing3D::IPrinting3DTextureResource> : produce_base<D, Windows::Graphics::Printing3D::IPrinting3DTextureResource>
{
    int32_t WINRT_CALL get_TextureData(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextureData, WINRT_WRAP(Windows::Storage::Streams::IRandomAccessStreamWithContentType));
            *value = detach_from<Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().TextureData());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TextureData(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextureData, WINRT_WRAP(void), Windows::Storage::Streams::IRandomAccessStreamWithContentType const&);
            this->shim().TextureData(*reinterpret_cast<Windows::Storage::Streams::IRandomAccessStreamWithContentType const*>(&value));
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
};

}

WINRT_EXPORT namespace winrt::Windows::Graphics::Printing3D {

inline Windows::Graphics::Printing3D::Print3DManager Print3DManager::GetForCurrentView()
{
    return impl::call_factory<Print3DManager, Windows::Graphics::Printing3D::IPrint3DManagerStatics>([&](auto&& f) { return f.GetForCurrentView(); });
}

inline Windows::Foundation::IAsyncOperation<bool> Print3DManager::ShowPrintUIAsync()
{
    return impl::call_factory<Print3DManager, Windows::Graphics::Printing3D::IPrint3DManagerStatics>([&](auto&& f) { return f.ShowPrintUIAsync(); });
}

inline Printing3D3MFPackage::Printing3D3MFPackage() :
    Printing3D3MFPackage(impl::call_factory<Printing3D3MFPackage>([](auto&& f) { return f.template ActivateInstance<Printing3D3MFPackage>(); }))
{}

inline Windows::Foundation::IAsyncOperation<Windows::Graphics::Printing3D::Printing3D3MFPackage> Printing3D3MFPackage::LoadAsync(Windows::Storage::Streams::IRandomAccessStream const& value)
{
    return impl::call_factory<Printing3D3MFPackage, Windows::Graphics::Printing3D::IPrinting3D3MFPackageStatics>([&](auto&& f) { return f.LoadAsync(value); });
}

inline Printing3DBaseMaterial::Printing3DBaseMaterial() :
    Printing3DBaseMaterial(impl::call_factory<Printing3DBaseMaterial>([](auto&& f) { return f.template ActivateInstance<Printing3DBaseMaterial>(); }))
{}

inline hstring Printing3DBaseMaterial::Abs()
{
    return impl::call_factory<Printing3DBaseMaterial, Windows::Graphics::Printing3D::IPrinting3DBaseMaterialStatics>([&](auto&& f) { return f.Abs(); });
}

inline hstring Printing3DBaseMaterial::Pla()
{
    return impl::call_factory<Printing3DBaseMaterial, Windows::Graphics::Printing3D::IPrinting3DBaseMaterialStatics>([&](auto&& f) { return f.Pla(); });
}

inline Printing3DBaseMaterialGroup::Printing3DBaseMaterialGroup(uint32_t MaterialGroupId) :
    Printing3DBaseMaterialGroup(impl::call_factory<Printing3DBaseMaterialGroup, Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroupFactory>([&](auto&& f) { return f.Create(MaterialGroupId); }))
{}

inline Printing3DColorMaterial::Printing3DColorMaterial() :
    Printing3DColorMaterial(impl::call_factory<Printing3DColorMaterial>([](auto&& f) { return f.template ActivateInstance<Printing3DColorMaterial>(); }))
{}

inline Printing3DColorMaterialGroup::Printing3DColorMaterialGroup(uint32_t MaterialGroupId) :
    Printing3DColorMaterialGroup(impl::call_factory<Printing3DColorMaterialGroup, Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroupFactory>([&](auto&& f) { return f.Create(MaterialGroupId); }))
{}

inline Printing3DComponent::Printing3DComponent() :
    Printing3DComponent(impl::call_factory<Printing3DComponent>([](auto&& f) { return f.template ActivateInstance<Printing3DComponent>(); }))
{}

inline Printing3DComponentWithMatrix::Printing3DComponentWithMatrix() :
    Printing3DComponentWithMatrix(impl::call_factory<Printing3DComponentWithMatrix>([](auto&& f) { return f.template ActivateInstance<Printing3DComponentWithMatrix>(); }))
{}

inline Printing3DCompositeMaterial::Printing3DCompositeMaterial() :
    Printing3DCompositeMaterial(impl::call_factory<Printing3DCompositeMaterial>([](auto&& f) { return f.template ActivateInstance<Printing3DCompositeMaterial>(); }))
{}

inline Printing3DCompositeMaterialGroup::Printing3DCompositeMaterialGroup(uint32_t MaterialGroupId) :
    Printing3DCompositeMaterialGroup(impl::call_factory<Printing3DCompositeMaterialGroup, Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroupFactory>([&](auto&& f) { return f.Create(MaterialGroupId); }))
{}

inline Printing3DFaceReductionOptions::Printing3DFaceReductionOptions() :
    Printing3DFaceReductionOptions(impl::call_factory<Printing3DFaceReductionOptions>([](auto&& f) { return f.template ActivateInstance<Printing3DFaceReductionOptions>(); }))
{}

inline Printing3DMaterial::Printing3DMaterial() :
    Printing3DMaterial(impl::call_factory<Printing3DMaterial>([](auto&& f) { return f.template ActivateInstance<Printing3DMaterial>(); }))
{}

inline Printing3DMesh::Printing3DMesh() :
    Printing3DMesh(impl::call_factory<Printing3DMesh>([](auto&& f) { return f.template ActivateInstance<Printing3DMesh>(); }))
{}

inline Printing3DModel::Printing3DModel() :
    Printing3DModel(impl::call_factory<Printing3DModel>([](auto&& f) { return f.template ActivateInstance<Printing3DModel>(); }))
{}

inline Printing3DModelTexture::Printing3DModelTexture() :
    Printing3DModelTexture(impl::call_factory<Printing3DModelTexture>([](auto&& f) { return f.template ActivateInstance<Printing3DModelTexture>(); }))
{}

inline Printing3DMultiplePropertyMaterial::Printing3DMultiplePropertyMaterial() :
    Printing3DMultiplePropertyMaterial(impl::call_factory<Printing3DMultiplePropertyMaterial>([](auto&& f) { return f.template ActivateInstance<Printing3DMultiplePropertyMaterial>(); }))
{}

inline Printing3DMultiplePropertyMaterialGroup::Printing3DMultiplePropertyMaterialGroup(uint32_t MaterialGroupId) :
    Printing3DMultiplePropertyMaterialGroup(impl::call_factory<Printing3DMultiplePropertyMaterialGroup, Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroupFactory>([&](auto&& f) { return f.Create(MaterialGroupId); }))
{}

inline Printing3DTexture2CoordMaterial::Printing3DTexture2CoordMaterial() :
    Printing3DTexture2CoordMaterial(impl::call_factory<Printing3DTexture2CoordMaterial>([](auto&& f) { return f.template ActivateInstance<Printing3DTexture2CoordMaterial>(); }))
{}

inline Printing3DTexture2CoordMaterialGroup::Printing3DTexture2CoordMaterialGroup(uint32_t MaterialGroupId) :
    Printing3DTexture2CoordMaterialGroup(impl::call_factory<Printing3DTexture2CoordMaterialGroup, Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroupFactory>([&](auto&& f) { return f.Create(MaterialGroupId); }))
{}

inline Printing3DTextureResource::Printing3DTextureResource() :
    Printing3DTextureResource(impl::call_factory<Printing3DTextureResource>([](auto&& f) { return f.template ActivateInstance<Printing3DTextureResource>(); }))
{}

template <typename L> Print3DTaskSourceRequestedHandler::Print3DTaskSourceRequestedHandler(L handler) :
    Print3DTaskSourceRequestedHandler(impl::make_delegate<Print3DTaskSourceRequestedHandler>(std::forward<L>(handler)))
{}

template <typename F> Print3DTaskSourceRequestedHandler::Print3DTaskSourceRequestedHandler(F* handler) :
    Print3DTaskSourceRequestedHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> Print3DTaskSourceRequestedHandler::Print3DTaskSourceRequestedHandler(O* object, M method) :
    Print3DTaskSourceRequestedHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> Print3DTaskSourceRequestedHandler::Print3DTaskSourceRequestedHandler(com_ptr<O>&& object, M method) :
    Print3DTaskSourceRequestedHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> Print3DTaskSourceRequestedHandler::Print3DTaskSourceRequestedHandler(weak_ref<O>&& object, M method) :
    Print3DTaskSourceRequestedHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void Print3DTaskSourceRequestedHandler::operator()(Windows::Graphics::Printing3D::Print3DTaskSourceRequestedArgs const& args) const
{
    check_hresult((*(impl::abi_t<Print3DTaskSourceRequestedHandler>**)this)->Invoke(get_abi(args)));
}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrint3DManager> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrint3DManager> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrint3DManagerStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrint3DManagerStatics> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrint3DTask> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrint3DTask> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrint3DTaskCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrint3DTaskCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrint3DTaskRequest> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrint3DTaskRequest> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrint3DTaskRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrint3DTaskRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrint3DTaskSourceChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrint3DTaskSourceChangedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrint3DTaskSourceRequestedArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrint3DTaskSourceRequestedArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3D3MFPackage> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3D3MFPackage> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3D3MFPackage2> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3D3MFPackage2> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3D3MFPackageStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3D3MFPackageStatics> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DBaseMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DBaseMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroup> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroup> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroupFactory> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DBaseMaterialGroupFactory> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DBaseMaterialStatics> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DBaseMaterialStatics> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DColorMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DColorMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DColorMaterial2> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DColorMaterial2> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroup> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroup> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroupFactory> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DColorMaterialGroupFactory> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DComponent> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DComponent> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DComponentWithMatrix> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DComponentWithMatrix> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DCompositeMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DCompositeMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup2> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroup2> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroupFactory> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DCompositeMaterialGroupFactory> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DFaceReductionOptions> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DFaceReductionOptions> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DMesh> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DMesh> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DMeshVerificationResult> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DMeshVerificationResult> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DModel> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DModel> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DModel2> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DModel2> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DModelTexture> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DModelTexture> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroup> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroup> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroupFactory> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DMultiplePropertyMaterialGroupFactory> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup2> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroup2> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroupFactory> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DTexture2CoordMaterialGroupFactory> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::IPrinting3DTextureResource> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::IPrinting3DTextureResource> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Print3DManager> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Print3DManager> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Print3DTask> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Print3DTask> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Print3DTaskCompletedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Print3DTaskCompletedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Print3DTaskRequest> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Print3DTaskRequest> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Print3DTaskRequestedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Print3DTaskRequestedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Print3DTaskSourceChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Print3DTaskSourceChangedEventArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Print3DTaskSourceRequestedArgs> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Print3DTaskSourceRequestedArgs> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3D3MFPackage> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3D3MFPackage> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DBaseMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DBaseMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DBaseMaterialGroup> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DColorMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DColorMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DColorMaterialGroup> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DColorMaterialGroup> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DComponent> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DComponent> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DComponentWithMatrix> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DComponentWithMatrix> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DCompositeMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DCompositeMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DCompositeMaterialGroup> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DCompositeMaterialGroup> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DFaceReductionOptions> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DFaceReductionOptions> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DMesh> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DMesh> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DMeshVerificationResult> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DMeshVerificationResult> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DModel> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DModel> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DModelTexture> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DModelTexture> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterialGroup> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DMultiplePropertyMaterialGroup> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterial> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterial> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterialGroup> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DTexture2CoordMaterialGroup> {};
template<> struct hash<winrt::Windows::Graphics::Printing3D::Printing3DTextureResource> : winrt::impl::hash_base<winrt::Windows::Graphics::Printing3D::Printing3DTextureResource> {};

}
