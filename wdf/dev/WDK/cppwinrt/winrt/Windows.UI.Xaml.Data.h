// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Interop.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Xaml.Data.2.h"
#include "winrt/Windows.UI.Xaml.h"

namespace winrt::impl {

template <typename D> Windows::UI::Xaml::PropertyPath consume_Windows_UI_Xaml_Data_IBinding<D>::Path() const
{
    Windows::UI::Xaml::PropertyPath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->get_Path(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBinding<D>::Path(Windows::UI::Xaml::PropertyPath const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->put_Path(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Data::BindingMode consume_Windows_UI_Xaml_Data_IBinding<D>::Mode() const
{
    Windows::UI::Xaml::Data::BindingMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBinding<D>::Mode(Windows::UI::Xaml::Data::BindingMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->put_Mode(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_IBinding<D>::Source() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBinding<D>::Source(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->put_Source(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Data::RelativeSource consume_Windows_UI_Xaml_Data_IBinding<D>::RelativeSource() const
{
    Windows::UI::Xaml::Data::RelativeSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->get_RelativeSource(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBinding<D>::RelativeSource(Windows::UI::Xaml::Data::RelativeSource const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->put_RelativeSource(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Data_IBinding<D>::ElementName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->get_ElementName(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBinding<D>::ElementName(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->put_ElementName(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Data::IValueConverter consume_Windows_UI_Xaml_Data_IBinding<D>::Converter() const
{
    Windows::UI::Xaml::Data::IValueConverter value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->get_Converter(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBinding<D>::Converter(Windows::UI::Xaml::Data::IValueConverter const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->put_Converter(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_IBinding<D>::ConverterParameter() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->get_ConverterParameter(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBinding<D>::ConverterParameter(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->put_ConverterParameter(get_abi(value)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Data_IBinding<D>::ConverterLanguage() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->get_ConverterLanguage(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBinding<D>::ConverterLanguage(param::hstring const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding)->put_ConverterLanguage(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_IBinding2<D>::FallbackValue() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding2)->get_FallbackValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBinding2<D>::FallbackValue(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding2)->put_FallbackValue(get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_IBinding2<D>::TargetNullValue() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding2)->get_TargetNullValue(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBinding2<D>::TargetNullValue(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding2)->put_TargetNullValue(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Data::UpdateSourceTrigger consume_Windows_UI_Xaml_Data_IBinding2<D>::UpdateSourceTrigger() const
{
    Windows::UI::Xaml::Data::UpdateSourceTrigger value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding2)->get_UpdateSourceTrigger(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBinding2<D>::UpdateSourceTrigger(Windows::UI::Xaml::Data::UpdateSourceTrigger const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBinding2)->put_UpdateSourceTrigger(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Data::BindingBase consume_Windows_UI_Xaml_Data_IBindingBaseFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Data::BindingBase value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBindingBaseFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_IBindingExpression<D>::DataItem() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBindingExpression)->get_DataItem(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Data::Binding consume_Windows_UI_Xaml_Data_IBindingExpression<D>::ParentBinding() const
{
    Windows::UI::Xaml::Data::Binding value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBindingExpression)->get_ParentBinding(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBindingExpression<D>::UpdateSource() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBindingExpression)->UpdateSource());
}

template <typename D> Windows::UI::Xaml::Data::Binding consume_Windows_UI_Xaml_Data_IBindingFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Data::Binding value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBindingFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IBindingOperationsStatics<D>::SetBinding(Windows::UI::Xaml::DependencyObject const& target, Windows::UI::Xaml::DependencyProperty const& dp, Windows::UI::Xaml::Data::BindingBase const& binding) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IBindingOperationsStatics)->SetBinding(get_abi(target), get_abi(dp), get_abi(binding)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentItem() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->get_CurrentItem(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentPosition() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->get_CurrentPosition(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICollectionView<D>::IsCurrentAfterLast() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->get_IsCurrentAfterLast(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICollectionView<D>::IsCurrentBeforeFirst() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->get_IsCurrentBeforeFirst(&value));
    return value;
}

template <typename D> Windows::Foundation::Collections::IObservableVector<Windows::Foundation::IInspectable> consume_Windows_UI_Xaml_Data_ICollectionView<D>::CollectionGroups() const
{
    Windows::Foundation::Collections::IObservableVector<Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->get_CollectionGroups(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICollectionView<D>::HasMoreItems() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->get_HasMoreItems(&value));
    return value;
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanged(Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->add_CurrentChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanged_revoker consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanged(auto_revoke_t, Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const& handler) const
{
    return impl::make_event_revoker<D, CurrentChanged_revoker>(this, CurrentChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->remove_CurrentChanged(get_abi(token)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanging(Windows::UI::Xaml::Data::CurrentChangingEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->add_CurrentChanging(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanging_revoker consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanging(auto_revoke_t, Windows::UI::Xaml::Data::CurrentChangingEventHandler const& handler) const
{
    return impl::make_event_revoker<D, CurrentChanging_revoker>(this, CurrentChanging(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Data_ICollectionView<D>::CurrentChanging(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->remove_CurrentChanging(get_abi(token)));
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentTo(Windows::Foundation::IInspectable const& item) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentTo(get_abi(item), &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentToPosition(int32_t index) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentToPosition(index, &result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentToFirst() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentToFirst(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentToLast() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentToLast(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentToNext() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentToNext(&result));
    return result;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICollectionView<D>::MoveCurrentToPrevious() const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->MoveCurrentToPrevious(&result));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Data::LoadMoreItemsResult> consume_Windows_UI_Xaml_Data_ICollectionView<D>::LoadMoreItemsAsync(uint32_t count) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Data::LoadMoreItemsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionView)->LoadMoreItemsAsync(count, put_abi(operation)));
    return operation;
}

template <typename D> Windows::UI::Xaml::Data::ICollectionView consume_Windows_UI_Xaml_Data_ICollectionViewFactory<D>::CreateView() const
{
    Windows::UI::Xaml::Data::ICollectionView result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewFactory)->CreateView(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_ICollectionViewGroup<D>::Group() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewGroup)->get_Group(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IObservableVector<Windows::Foundation::IInspectable> consume_Windows_UI_Xaml_Data_ICollectionViewGroup<D>::GroupItems() const
{
    Windows::Foundation::Collections::IObservableVector<Windows::Foundation::IInspectable> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewGroup)->get_GroupItems(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::Source() const
{
    Windows::Foundation::IInspectable value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewSource)->get_Source(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::Source(Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewSource)->put_Source(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Data::ICollectionView consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::View() const
{
    Windows::UI::Xaml::Data::ICollectionView value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewSource)->get_View(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::IsSourceGrouped() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewSource)->get_IsSourceGrouped(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::IsSourceGrouped(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewSource)->put_IsSourceGrouped(value));
}

template <typename D> Windows::UI::Xaml::PropertyPath consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::ItemsPath() const
{
    Windows::UI::Xaml::PropertyPath value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewSource)->get_ItemsPath(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_ICollectionViewSource<D>::ItemsPath(Windows::UI::Xaml::PropertyPath const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewSource)->put_ItemsPath(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Data_ICollectionViewSourceStatics<D>::SourceProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewSourceStatics)->get_SourceProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Data_ICollectionViewSourceStatics<D>::ViewProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewSourceStatics)->get_ViewProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Data_ICollectionViewSourceStatics<D>::IsSourceGroupedProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewSourceStatics)->get_IsSourceGroupedProperty(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::DependencyProperty consume_Windows_UI_Xaml_Data_ICollectionViewSourceStatics<D>::ItemsPathProperty() const
{
    Windows::UI::Xaml::DependencyProperty value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICollectionViewSourceStatics)->get_ItemsPathProperty(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICurrentChangingEventArgs<D>::Cancel() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICurrentChangingEventArgs)->get_Cancel(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_ICurrentChangingEventArgs<D>::Cancel(bool value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICurrentChangingEventArgs)->put_Cancel(value));
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICurrentChangingEventArgs<D>::IsCancelable() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICurrentChangingEventArgs)->get_IsCancelable(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Data::CurrentChangingEventArgs consume_Windows_UI_Xaml_Data_ICurrentChangingEventArgsFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Data::CurrentChangingEventArgs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Data::CurrentChangingEventArgs consume_Windows_UI_Xaml_Data_ICurrentChangingEventArgsFactory<D>::CreateWithCancelableParameter(bool isCancelable, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Data::CurrentChangingEventArgs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory)->CreateWithCancelableParameter(isCancelable, get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Interop::TypeName consume_Windows_UI_Xaml_Data_ICustomProperty<D>::Type() const
{
    Windows::UI::Xaml::Interop::TypeName value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomProperty)->get_Type(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Xaml_Data_ICustomProperty<D>::Name() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomProperty)->get_Name(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_ICustomProperty<D>::GetValue(Windows::Foundation::IInspectable const& target) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomProperty)->GetValue(get_abi(target), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Data_ICustomProperty<D>::SetValue(Windows::Foundation::IInspectable const& target, Windows::Foundation::IInspectable const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomProperty)->SetValue(get_abi(target), get_abi(value)));
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_ICustomProperty<D>::GetIndexedValue(Windows::Foundation::IInspectable const& target, Windows::Foundation::IInspectable const& index) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomProperty)->GetIndexedValue(get_abi(target), get_abi(index), put_abi(result)));
    return result;
}

template <typename D> void consume_Windows_UI_Xaml_Data_ICustomProperty<D>::SetIndexedValue(Windows::Foundation::IInspectable const& target, Windows::Foundation::IInspectable const& value, Windows::Foundation::IInspectable const& index) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomProperty)->SetIndexedValue(get_abi(target), get_abi(value), get_abi(index)));
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICustomProperty<D>::CanWrite() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomProperty)->get_CanWrite(&value));
    return value;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ICustomProperty<D>::CanRead() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomProperty)->get_CanRead(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Data::ICustomProperty consume_Windows_UI_Xaml_Data_ICustomPropertyProvider<D>::GetCustomProperty(param::hstring const& name) const
{
    Windows::UI::Xaml::Data::ICustomProperty result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomPropertyProvider)->GetCustomProperty(get_abi(name), put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Data::ICustomProperty consume_Windows_UI_Xaml_Data_ICustomPropertyProvider<D>::GetIndexedProperty(param::hstring const& name, Windows::UI::Xaml::Interop::TypeName const& type) const
{
    Windows::UI::Xaml::Data::ICustomProperty result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomPropertyProvider)->GetIndexedProperty(get_abi(name), get_abi(type), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Xaml_Data_ICustomPropertyProvider<D>::GetStringRepresentation() const
{
    hstring result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomPropertyProvider)->GetStringRepresentation(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Xaml::Interop::TypeName consume_Windows_UI_Xaml_Data_ICustomPropertyProvider<D>::Type() const
{
    Windows::UI::Xaml::Interop::TypeName value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ICustomPropertyProvider)->get_Type(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Data_IItemIndexRange<D>::FirstIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IItemIndexRange)->get_FirstIndex(&value));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Xaml_Data_IItemIndexRange<D>::Length() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IItemIndexRange)->get_Length(&value));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Xaml_Data_IItemIndexRange<D>::LastIndex() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IItemIndexRange)->get_LastIndex(&value));
    return value;
}

template <typename D> Windows::UI::Xaml::Data::ItemIndexRange consume_Windows_UI_Xaml_Data_IItemIndexRangeFactory<D>::CreateInstance(int32_t firstIndex, uint32_t length, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Data::ItemIndexRange value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IItemIndexRangeFactory)->CreateInstance(firstIndex, length, get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IItemsRangeInfo<D>::RangesChanged(Windows::UI::Xaml::Data::ItemIndexRange const& visibleRange, param::vector_view<Windows::UI::Xaml::Data::ItemIndexRange> const& trackedItems) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IItemsRangeInfo)->RangesChanged(get_abi(visibleRange), get_abi(trackedItems)));
}

template <typename D> winrt::event_token consume_Windows_UI_Xaml_Data_INotifyPropertyChanged<D>::PropertyChanged(Windows::UI::Xaml::Data::PropertyChangedEventHandler const& handler) const
{
    winrt::event_token token{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::INotifyPropertyChanged)->add_PropertyChanged(get_abi(handler), put_abi(token)));
    return token;
}

template <typename D> typename consume_Windows_UI_Xaml_Data_INotifyPropertyChanged<D>::PropertyChanged_revoker consume_Windows_UI_Xaml_Data_INotifyPropertyChanged<D>::PropertyChanged(auto_revoke_t, Windows::UI::Xaml::Data::PropertyChangedEventHandler const& handler) const
{
    return impl::make_event_revoker<D, PropertyChanged_revoker>(this, PropertyChanged(handler));
}

template <typename D> void consume_Windows_UI_Xaml_Data_INotifyPropertyChanged<D>::PropertyChanged(winrt::event_token const& token) const noexcept
{
    WINRT_VERIFY_(0, WINRT_SHIM(Windows::UI::Xaml::Data::INotifyPropertyChanged)->remove_PropertyChanged(get_abi(token)));
}

template <typename D> hstring consume_Windows_UI_Xaml_Data_IPropertyChangedEventArgs<D>::PropertyName() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IPropertyChangedEventArgs)->get_PropertyName(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Data::PropertyChangedEventArgs consume_Windows_UI_Xaml_Data_IPropertyChangedEventArgsFactory<D>::CreateInstance(param::hstring const& name, Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Data::PropertyChangedEventArgs value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IPropertyChangedEventArgsFactory)->CreateInstance(get_abi(name), get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Xaml::Data::RelativeSourceMode consume_Windows_UI_Xaml_Data_IRelativeSource<D>::Mode() const
{
    Windows::UI::Xaml::Data::RelativeSourceMode value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IRelativeSource)->get_Mode(put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_IRelativeSource<D>::Mode(Windows::UI::Xaml::Data::RelativeSourceMode const& value) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IRelativeSource)->put_Mode(get_abi(value)));
}

template <typename D> Windows::UI::Xaml::Data::RelativeSource consume_Windows_UI_Xaml_Data_IRelativeSourceFactory<D>::CreateInstance(Windows::Foundation::IInspectable const& baseInterface, Windows::Foundation::IInspectable& innerInterface) const
{
    Windows::UI::Xaml::Data::RelativeSource value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IRelativeSourceFactory)->CreateInstance(get_abi(baseInterface), put_abi(innerInterface), put_abi(value)));
    return value;
}

template <typename D> void consume_Windows_UI_Xaml_Data_ISelectionInfo<D>::SelectRange(Windows::UI::Xaml::Data::ItemIndexRange const& itemIndexRange) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ISelectionInfo)->SelectRange(get_abi(itemIndexRange)));
}

template <typename D> void consume_Windows_UI_Xaml_Data_ISelectionInfo<D>::DeselectRange(Windows::UI::Xaml::Data::ItemIndexRange const& itemIndexRange) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ISelectionInfo)->DeselectRange(get_abi(itemIndexRange)));
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ISelectionInfo<D>::IsSelected(int32_t index) const
{
    bool result{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ISelectionInfo)->IsSelected(index, &result));
    return result;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Data::ItemIndexRange> consume_Windows_UI_Xaml_Data_ISelectionInfo<D>::GetSelectedRanges() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Data::ItemIndexRange> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ISelectionInfo)->GetSelectedRanges(put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Data::LoadMoreItemsResult> consume_Windows_UI_Xaml_Data_ISupportIncrementalLoading<D>::LoadMoreItemsAsync(uint32_t count) const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Data::LoadMoreItemsResult> operation{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ISupportIncrementalLoading)->LoadMoreItemsAsync(count, put_abi(operation)));
    return operation;
}

template <typename D> bool consume_Windows_UI_Xaml_Data_ISupportIncrementalLoading<D>::HasMoreItems() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::ISupportIncrementalLoading)->get_HasMoreItems(&value));
    return value;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_IValueConverter<D>::Convert(Windows::Foundation::IInspectable const& value, Windows::UI::Xaml::Interop::TypeName const& targetType, Windows::Foundation::IInspectable const& parameter, param::hstring const& language) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IValueConverter)->Convert(get_abi(value), get_abi(targetType), get_abi(parameter), get_abi(language), put_abi(result)));
    return result;
}

template <typename D> Windows::Foundation::IInspectable consume_Windows_UI_Xaml_Data_IValueConverter<D>::ConvertBack(Windows::Foundation::IInspectable const& value, Windows::UI::Xaml::Interop::TypeName const& targetType, Windows::Foundation::IInspectable const& parameter, param::hstring const& language) const
{
    Windows::Foundation::IInspectable result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Xaml::Data::IValueConverter)->ConvertBack(get_abi(value), get_abi(targetType), get_abi(parameter), get_abi(language), put_abi(result)));
    return result;
}

template <> struct delegate<Windows::UI::Xaml::Data::CurrentChangingEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Data::CurrentChangingEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Data::CurrentChangingEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Data::CurrentChangingEventArgs const*>(&e));
                return 0;
            }
            catch (...)
            {
                return to_hresult();
            }
        }
    };
};

template <> struct delegate<Windows::UI::Xaml::Data::PropertyChangedEventHandler>
{
    template <typename H>
    struct type : implements_delegate<Windows::UI::Xaml::Data::PropertyChangedEventHandler, H>
    {
        type(H&& handler) : implements_delegate<Windows::UI::Xaml::Data::PropertyChangedEventHandler, H>(std::forward<H>(handler)) {}

        int32_t WINRT_CALL Invoke(void* sender, void* e) noexcept final
        {
            try
            {
                (*this)(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<Windows::UI::Xaml::Data::PropertyChangedEventArgs const*>(&e));
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
struct produce<D, Windows::UI::Xaml::Data::IBinding> : produce_base<D, Windows::UI::Xaml::Data::IBinding>
{
    int32_t WINRT_CALL get_Path(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(Windows::UI::Xaml::PropertyPath));
            *value = detach_from<Windows::UI::Xaml::PropertyPath>(this->shim().Path());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Path(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Path, WINRT_WRAP(void), Windows::UI::Xaml::PropertyPath const&);
            this->shim().Path(*reinterpret_cast<Windows::UI::Xaml::PropertyPath const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Mode(Windows::UI::Xaml::Data::BindingMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::UI::Xaml::Data::BindingMode));
            *value = detach_from<Windows::UI::Xaml::Data::BindingMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::UI::Xaml::Data::BindingMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::UI::Xaml::Data::BindingMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::UI::Xaml::Data::BindingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Source(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Source(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RelativeSource(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeSource, WINRT_WRAP(Windows::UI::Xaml::Data::RelativeSource));
            *value = detach_from<Windows::UI::Xaml::Data::RelativeSource>(this->shim().RelativeSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_RelativeSource(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RelativeSource, WINRT_WRAP(void), Windows::UI::Xaml::Data::RelativeSource const&);
            this->shim().RelativeSource(*reinterpret_cast<Windows::UI::Xaml::Data::RelativeSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ElementName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ElementName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ElementName(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ElementName, WINRT_WRAP(void), hstring const&);
            this->shim().ElementName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Converter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Converter, WINRT_WRAP(Windows::UI::Xaml::Data::IValueConverter));
            *value = detach_from<Windows::UI::Xaml::Data::IValueConverter>(this->shim().Converter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Converter(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Converter, WINRT_WRAP(void), Windows::UI::Xaml::Data::IValueConverter const&);
            this->shim().Converter(*reinterpret_cast<Windows::UI::Xaml::Data::IValueConverter const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConverterParameter(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConverterParameter, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().ConverterParameter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ConverterParameter(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConverterParameter, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().ConverterParameter(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ConverterLanguage(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConverterLanguage, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().ConverterLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ConverterLanguage(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConverterLanguage, WINRT_WRAP(void), hstring const&);
            this->shim().ConverterLanguage(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IBinding2> : produce_base<D, Windows::UI::Xaml::Data::IBinding2>
{
    int32_t WINRT_CALL get_FallbackValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FallbackValue, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().FallbackValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_FallbackValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FallbackValue, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().FallbackValue(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TargetNullValue(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNullValue, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().TargetNullValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_TargetNullValue(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TargetNullValue, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().TargetNullValue(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_UpdateSourceTrigger(Windows::UI::Xaml::Data::UpdateSourceTrigger* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateSourceTrigger, WINRT_WRAP(Windows::UI::Xaml::Data::UpdateSourceTrigger));
            *value = detach_from<Windows::UI::Xaml::Data::UpdateSourceTrigger>(this->shim().UpdateSourceTrigger());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_UpdateSourceTrigger(Windows::UI::Xaml::Data::UpdateSourceTrigger value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateSourceTrigger, WINRT_WRAP(void), Windows::UI::Xaml::Data::UpdateSourceTrigger const&);
            this->shim().UpdateSourceTrigger(*reinterpret_cast<Windows::UI::Xaml::Data::UpdateSourceTrigger const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IBindingBase> : produce_base<D, Windows::UI::Xaml::Data::IBindingBase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IBindingBaseFactory> : produce_base<D, Windows::UI::Xaml::Data::IBindingBaseFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Data::BindingBase), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Data::BindingBase>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IBindingExpression> : produce_base<D, Windows::UI::Xaml::Data::IBindingExpression>
{
    int32_t WINRT_CALL get_DataItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DataItem, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().DataItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ParentBinding(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ParentBinding, WINRT_WRAP(Windows::UI::Xaml::Data::Binding));
            *value = detach_from<Windows::UI::Xaml::Data::Binding>(this->shim().ParentBinding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL UpdateSource() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(UpdateSource, WINRT_WRAP(void));
            this->shim().UpdateSource();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IBindingExpressionBase> : produce_base<D, Windows::UI::Xaml::Data::IBindingExpressionBase>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IBindingExpressionBaseFactory> : produce_base<D, Windows::UI::Xaml::Data::IBindingExpressionBaseFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IBindingExpressionFactory> : produce_base<D, Windows::UI::Xaml::Data::IBindingExpressionFactory>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IBindingFactory> : produce_base<D, Windows::UI::Xaml::Data::IBindingFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Data::Binding), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Data::Binding>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IBindingOperations> : produce_base<D, Windows::UI::Xaml::Data::IBindingOperations>
{};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IBindingOperationsStatics> : produce_base<D, Windows::UI::Xaml::Data::IBindingOperationsStatics>
{
    int32_t WINRT_CALL SetBinding(void* target, void* dp, void* binding) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetBinding, WINRT_WRAP(void), Windows::UI::Xaml::DependencyObject const&, Windows::UI::Xaml::DependencyProperty const&, Windows::UI::Xaml::Data::BindingBase const&);
            this->shim().SetBinding(*reinterpret_cast<Windows::UI::Xaml::DependencyObject const*>(&target), *reinterpret_cast<Windows::UI::Xaml::DependencyProperty const*>(&dp), *reinterpret_cast<Windows::UI::Xaml::Data::BindingBase const*>(&binding));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::ICollectionView> : produce_base<D, Windows::UI::Xaml::Data::ICollectionView>
{
    int32_t WINRT_CALL get_CurrentItem(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentItem, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().CurrentItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CurrentPosition(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentPosition, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().CurrentPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCurrentAfterLast(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCurrentAfterLast, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCurrentAfterLast());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCurrentBeforeFirst(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCurrentBeforeFirst, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCurrentBeforeFirst());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CollectionGroups(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CollectionGroups, WINRT_WRAP(Windows::Foundation::Collections::IObservableVector<Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IObservableVector<Windows::Foundation::IInspectable>>(this->shim().CollectionGroups());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasMoreItems(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasMoreItems, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasMoreItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL add_CurrentChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentChanged, WINRT_WRAP(winrt::event_token), Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const&);
            *token = detach_from<winrt::event_token>(this->shim().CurrentChanged(*reinterpret_cast<Windows::Foundation::EventHandler<Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CurrentChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CurrentChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CurrentChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL add_CurrentChanging(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CurrentChanging, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Data::CurrentChangingEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().CurrentChanging(*reinterpret_cast<Windows::UI::Xaml::Data::CurrentChangingEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_CurrentChanging(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(CurrentChanging, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().CurrentChanging(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }

    int32_t WINRT_CALL MoveCurrentTo(void* item, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveCurrentTo, WINRT_WRAP(bool), Windows::Foundation::IInspectable const&);
            *result = detach_from<bool>(this->shim().MoveCurrentTo(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&item)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveCurrentToPosition(int32_t index, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveCurrentToPosition, WINRT_WRAP(bool), int32_t);
            *result = detach_from<bool>(this->shim().MoveCurrentToPosition(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveCurrentToFirst(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveCurrentToFirst, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().MoveCurrentToFirst());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveCurrentToLast(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveCurrentToLast, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().MoveCurrentToLast());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveCurrentToNext(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveCurrentToNext, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().MoveCurrentToNext());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL MoveCurrentToPrevious(bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(MoveCurrentToPrevious, WINRT_WRAP(bool));
            *result = detach_from<bool>(this->shim().MoveCurrentToPrevious());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL LoadMoreItemsAsync(uint32_t count, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadMoreItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Data::LoadMoreItemsResult>), uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Data::LoadMoreItemsResult>>(this->shim().LoadMoreItemsAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::ICollectionViewFactory> : produce_base<D, Windows::UI::Xaml::Data::ICollectionViewFactory>
{
    int32_t WINRT_CALL CreateView(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateView, WINRT_WRAP(Windows::UI::Xaml::Data::ICollectionView));
            *result = detach_from<Windows::UI::Xaml::Data::ICollectionView>(this->shim().CreateView());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::ICollectionViewGroup> : produce_base<D, Windows::UI::Xaml::Data::ICollectionViewGroup>
{
    int32_t WINRT_CALL get_Group(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Group, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Group());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_GroupItems(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GroupItems, WINRT_WRAP(Windows::Foundation::Collections::IObservableVector<Windows::Foundation::IInspectable>));
            *value = detach_from<Windows::Foundation::Collections::IObservableVector<Windows::Foundation::IInspectable>>(this->shim().GroupItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::ICollectionViewSource> : produce_base<D, Windows::UI::Xaml::Data::ICollectionViewSource>
{
    int32_t WINRT_CALL get_Source(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(Windows::Foundation::IInspectable));
            *value = detach_from<Windows::Foundation::IInspectable>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Source(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Source, WINRT_WRAP(void), Windows::Foundation::IInspectable const&);
            this->shim().Source(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_View(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(View, WINRT_WRAP(Windows::UI::Xaml::Data::ICollectionView));
            *value = detach_from<Windows::UI::Xaml::Data::ICollectionView>(this->shim().View());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSourceGrouped(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSourceGrouped, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsSourceGrouped());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_IsSourceGrouped(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSourceGrouped, WINRT_WRAP(void), bool);
            this->shim().IsSourceGrouped(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemsPath(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsPath, WINRT_WRAP(Windows::UI::Xaml::PropertyPath));
            *value = detach_from<Windows::UI::Xaml::PropertyPath>(this->shim().ItemsPath());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_ItemsPath(void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsPath, WINRT_WRAP(void), Windows::UI::Xaml::PropertyPath const&);
            this->shim().ItemsPath(*reinterpret_cast<Windows::UI::Xaml::PropertyPath const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::ICollectionViewSourceStatics> : produce_base<D, Windows::UI::Xaml::Data::ICollectionViewSourceStatics>
{
    int32_t WINRT_CALL get_SourceProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SourceProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().SourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ViewProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ViewProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ViewProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsSourceGroupedProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSourceGroupedProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().IsSourceGroupedProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_ItemsPathProperty(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ItemsPathProperty, WINRT_WRAP(Windows::UI::Xaml::DependencyProperty));
            *value = detach_from<Windows::UI::Xaml::DependencyProperty>(this->shim().ItemsPathProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::ICurrentChangingEventArgs> : produce_base<D, Windows::UI::Xaml::Data::ICurrentChangingEventArgs>
{
    int32_t WINRT_CALL get_Cancel(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().Cancel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Cancel(bool value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Cancel, WINRT_WRAP(void), bool);
            this->shim().Cancel(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsCancelable(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsCancelable, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsCancelable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory> : produce_base<D, Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Data::CurrentChangingEventArgs), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Data::CurrentChangingEventArgs>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL CreateWithCancelableParameter(bool isCancelable, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateWithCancelableParameter, WINRT_WRAP(Windows::UI::Xaml::Data::CurrentChangingEventArgs), bool, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Data::CurrentChangingEventArgs>(this->shim().CreateWithCancelableParameter(isCancelable, *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::ICustomProperty> : produce_base<D, Windows::UI::Xaml::Data::ICustomProperty>
{
    int32_t WINRT_CALL get_Type(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::UI::Xaml::Interop::TypeName));
            *value = detach_from<Windows::UI::Xaml::Interop::TypeName>(this->shim().Type());
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

    int32_t WINRT_CALL GetValue(void* target, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetValue, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetValue(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetValue(void* target, void* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetValue, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&);
            this->shim().SetValue(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&target), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIndexedValue(void* target, void* index, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIndexedValue, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().GetIndexedValue(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&target), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&index)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetIndexedValue(void* target, void* value, void* index) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetIndexedValue, WINRT_WRAP(void), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable const&);
            this->shim().SetIndexedValue(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&target), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&value), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanWrite(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanWrite, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanWrite());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_CanRead(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CanRead, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().CanRead());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::ICustomPropertyProvider> : produce_base<D, Windows::UI::Xaml::Data::ICustomPropertyProvider>
{
    int32_t WINRT_CALL GetCustomProperty(void* name, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetCustomProperty, WINRT_WRAP(Windows::UI::Xaml::Data::ICustomProperty), hstring const&);
            *result = detach_from<Windows::UI::Xaml::Data::ICustomProperty>(this->shim().GetCustomProperty(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetIndexedProperty(void* name, struct struct_Windows_UI_Xaml_Interop_TypeName type, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetIndexedProperty, WINRT_WRAP(Windows::UI::Xaml::Data::ICustomProperty), hstring const&, Windows::UI::Xaml::Interop::TypeName const&);
            *result = detach_from<Windows::UI::Xaml::Data::ICustomProperty>(this->shim().GetIndexedProperty(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStringRepresentation(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStringRepresentation, WINRT_WRAP(hstring));
            *result = detach_from<hstring>(this->shim().GetStringRepresentation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Type(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Type, WINRT_WRAP(Windows::UI::Xaml::Interop::TypeName));
            *value = detach_from<Windows::UI::Xaml::Interop::TypeName>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IItemIndexRange> : produce_base<D, Windows::UI::Xaml::Data::IItemIndexRange>
{
    int32_t WINRT_CALL get_FirstIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FirstIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().FirstIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Length(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Length, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_LastIndex(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LastIndex, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().LastIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IItemIndexRangeFactory> : produce_base<D, Windows::UI::Xaml::Data::IItemIndexRangeFactory>
{
    int32_t WINRT_CALL CreateInstance(int32_t firstIndex, uint32_t length, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Data::ItemIndexRange), int32_t, uint32_t, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Data::ItemIndexRange>(this->shim().CreateInstance(firstIndex, length, *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IItemsRangeInfo> : produce_base<D, Windows::UI::Xaml::Data::IItemsRangeInfo>
{
    int32_t WINRT_CALL RangesChanged(void* visibleRange, void* trackedItems) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RangesChanged, WINRT_WRAP(void), Windows::UI::Xaml::Data::ItemIndexRange const&, Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Data::ItemIndexRange> const&);
            this->shim().RangesChanged(*reinterpret_cast<Windows::UI::Xaml::Data::ItemIndexRange const*>(&visibleRange), *reinterpret_cast<Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Data::ItemIndexRange> const*>(&trackedItems));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::INotifyPropertyChanged> : produce_base<D, Windows::UI::Xaml::Data::INotifyPropertyChanged>
{
    int32_t WINRT_CALL add_PropertyChanged(void* handler, winrt::event_token* token) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PropertyChanged, WINRT_WRAP(winrt::event_token), Windows::UI::Xaml::Data::PropertyChangedEventHandler const&);
            *token = detach_from<winrt::event_token>(this->shim().PropertyChanged(*reinterpret_cast<Windows::UI::Xaml::Data::PropertyChangedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL remove_PropertyChanged(winrt::event_token token) noexcept final
    {
        typename D::abi_guard guard(this->shim());
        WINRT_ASSERT_DECLARATION(PropertyChanged, WINRT_WRAP(void), winrt::event_token const&);
        this->shim().PropertyChanged(*reinterpret_cast<winrt::event_token const*>(&token));
        return 0;
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IPropertyChangedEventArgs> : produce_base<D, Windows::UI::Xaml::Data::IPropertyChangedEventArgs>
{
    int32_t WINRT_CALL get_PropertyName(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(PropertyName, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().PropertyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IPropertyChangedEventArgsFactory> : produce_base<D, Windows::UI::Xaml::Data::IPropertyChangedEventArgsFactory>
{
    int32_t WINRT_CALL CreateInstance(void* name, void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Data::PropertyChangedEventArgs), hstring const&, Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Data::PropertyChangedEventArgs>(this->shim().CreateInstance(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IRelativeSource> : produce_base<D, Windows::UI::Xaml::Data::IRelativeSource>
{
    int32_t WINRT_CALL get_Mode(Windows::UI::Xaml::Data::RelativeSourceMode* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(Windows::UI::Xaml::Data::RelativeSourceMode));
            *value = detach_from<Windows::UI::Xaml::Data::RelativeSourceMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL put_Mode(Windows::UI::Xaml::Data::RelativeSourceMode value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Mode, WINRT_WRAP(void), Windows::UI::Xaml::Data::RelativeSourceMode const&);
            this->shim().Mode(*reinterpret_cast<Windows::UI::Xaml::Data::RelativeSourceMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IRelativeSourceFactory> : produce_base<D, Windows::UI::Xaml::Data::IRelativeSourceFactory>
{
    int32_t WINRT_CALL CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final
    {
        try
        {
            if (innerInterface) *innerInterface = nullptr;
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            Windows::Foundation::IInspectable __local_innerInterface;
            WINRT_ASSERT_DECLARATION(CreateInstance, WINRT_WRAP(Windows::UI::Xaml::Data::RelativeSource), Windows::Foundation::IInspectable const&, Windows::Foundation::IInspectable&);
            *value = detach_from<Windows::UI::Xaml::Data::RelativeSource>(this->shim().CreateInstance(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&baseInterface), __local_innerInterface));
            if (innerInterface) *innerInterface = detach_abi(__local_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::ISelectionInfo> : produce_base<D, Windows::UI::Xaml::Data::ISelectionInfo>
{
    int32_t WINRT_CALL SelectRange(void* itemIndexRange) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SelectRange, WINRT_WRAP(void), Windows::UI::Xaml::Data::ItemIndexRange const&);
            this->shim().SelectRange(*reinterpret_cast<Windows::UI::Xaml::Data::ItemIndexRange const*>(&itemIndexRange));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL DeselectRange(void* itemIndexRange) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DeselectRange, WINRT_WRAP(void), Windows::UI::Xaml::Data::ItemIndexRange const&);
            this->shim().DeselectRange(*reinterpret_cast<Windows::UI::Xaml::Data::ItemIndexRange const*>(&itemIndexRange));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL IsSelected(int32_t index, bool* result) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsSelected, WINRT_WRAP(bool), int32_t);
            *result = detach_from<bool>(this->shim().IsSelected(index));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetSelectedRanges(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetSelectedRanges, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Data::ItemIndexRange>));
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Xaml::Data::ItemIndexRange>>(this->shim().GetSelectedRanges());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::ISupportIncrementalLoading> : produce_base<D, Windows::UI::Xaml::Data::ISupportIncrementalLoading>
{
    int32_t WINRT_CALL LoadMoreItemsAsync(uint32_t count, void** operation) noexcept final
    {
        try
        {
            *operation = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(LoadMoreItemsAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Data::LoadMoreItemsResult>), uint32_t);
            *operation = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Xaml::Data::LoadMoreItemsResult>>(this->shim().LoadMoreItemsAsync(count));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_HasMoreItems(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(HasMoreItems, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().HasMoreItems());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Xaml::Data::IValueConverter> : produce_base<D, Windows::UI::Xaml::Data::IValueConverter>
{
    int32_t WINRT_CALL Convert(void* value, struct struct_Windows_UI_Xaml_Interop_TypeName targetType, void* parameter, void* language, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Convert, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::Interop::TypeName const&, Windows::Foundation::IInspectable const&, hstring const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().Convert(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value), *reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&targetType), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&parameter), *reinterpret_cast<hstring const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ConvertBack(void* value, struct struct_Windows_UI_Xaml_Interop_TypeName targetType, void* parameter, void* language, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ConvertBack, WINRT_WRAP(Windows::Foundation::IInspectable), Windows::Foundation::IInspectable const&, Windows::UI::Xaml::Interop::TypeName const&, Windows::Foundation::IInspectable const&, hstring const&);
            *result = detach_from<Windows::Foundation::IInspectable>(this->shim().ConvertBack(*reinterpret_cast<Windows::Foundation::IInspectable const*>(&value), *reinterpret_cast<Windows::UI::Xaml::Interop::TypeName const*>(&targetType), *reinterpret_cast<Windows::Foundation::IInspectable const*>(&parameter), *reinterpret_cast<hstring const*>(&language)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Data {

inline Binding::Binding()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<Binding, Windows::UI::Xaml::Data::IBindingFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline BindingBase::BindingBase()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<BindingBase, Windows::UI::Xaml::Data::IBindingBaseFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline void BindingOperations::SetBinding(Windows::UI::Xaml::DependencyObject const& target, Windows::UI::Xaml::DependencyProperty const& dp, Windows::UI::Xaml::Data::BindingBase const& binding)
{
    impl::call_factory<BindingOperations, Windows::UI::Xaml::Data::IBindingOperationsStatics>([&](auto&& f) { return f.SetBinding(target, dp, binding); });
}

inline CollectionViewSource::CollectionViewSource() :
    CollectionViewSource(impl::call_factory<CollectionViewSource>([](auto&& f) { return f.template ActivateInstance<CollectionViewSource>(); }))
{}

inline Windows::UI::Xaml::DependencyProperty CollectionViewSource::SourceProperty()
{
    return impl::call_factory<CollectionViewSource, Windows::UI::Xaml::Data::ICollectionViewSourceStatics>([&](auto&& f) { return f.SourceProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CollectionViewSource::ViewProperty()
{
    return impl::call_factory<CollectionViewSource, Windows::UI::Xaml::Data::ICollectionViewSourceStatics>([&](auto&& f) { return f.ViewProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CollectionViewSource::IsSourceGroupedProperty()
{
    return impl::call_factory<CollectionViewSource, Windows::UI::Xaml::Data::ICollectionViewSourceStatics>([&](auto&& f) { return f.IsSourceGroupedProperty(); });
}

inline Windows::UI::Xaml::DependencyProperty CollectionViewSource::ItemsPathProperty()
{
    return impl::call_factory<CollectionViewSource, Windows::UI::Xaml::Data::ICollectionViewSourceStatics>([&](auto&& f) { return f.ItemsPathProperty(); });
}

inline CurrentChangingEventArgs::CurrentChangingEventArgs()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<CurrentChangingEventArgs, Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

inline CurrentChangingEventArgs::CurrentChangingEventArgs(bool isCancelable)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<CurrentChangingEventArgs, Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory>([&](auto&& f) { return f.CreateWithCancelableParameter(isCancelable, baseInterface, innerInterface); });
}

inline ItemIndexRange::ItemIndexRange(int32_t firstIndex, uint32_t length)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<ItemIndexRange, Windows::UI::Xaml::Data::IItemIndexRangeFactory>([&](auto&& f) { return f.CreateInstance(firstIndex, length, baseInterface, innerInterface); });
}

inline PropertyChangedEventArgs::PropertyChangedEventArgs(param::hstring const& name)
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<PropertyChangedEventArgs, Windows::UI::Xaml::Data::IPropertyChangedEventArgsFactory>([&](auto&& f) { return f.CreateInstance(name, baseInterface, innerInterface); });
}

inline RelativeSource::RelativeSource()
{
    Windows::Foundation::IInspectable baseInterface, innerInterface;
    *this = impl::call_factory<RelativeSource, Windows::UI::Xaml::Data::IRelativeSourceFactory>([&](auto&& f) { return f.CreateInstance(baseInterface, innerInterface); });
}

template <typename L> CurrentChangingEventHandler::CurrentChangingEventHandler(L handler) :
    CurrentChangingEventHandler(impl::make_delegate<CurrentChangingEventHandler>(std::forward<L>(handler)))
{}

template <typename F> CurrentChangingEventHandler::CurrentChangingEventHandler(F* handler) :
    CurrentChangingEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> CurrentChangingEventHandler::CurrentChangingEventHandler(O* object, M method) :
    CurrentChangingEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> CurrentChangingEventHandler::CurrentChangingEventHandler(com_ptr<O>&& object, M method) :
    CurrentChangingEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> CurrentChangingEventHandler::CurrentChangingEventHandler(weak_ref<O>&& object, M method) :
    CurrentChangingEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void CurrentChangingEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Data::CurrentChangingEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<CurrentChangingEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename L> PropertyChangedEventHandler::PropertyChangedEventHandler(L handler) :
    PropertyChangedEventHandler(impl::make_delegate<PropertyChangedEventHandler>(std::forward<L>(handler)))
{}

template <typename F> PropertyChangedEventHandler::PropertyChangedEventHandler(F* handler) :
    PropertyChangedEventHandler([=](auto&&... args) { return handler(args...); })
{}

template <typename O, typename M> PropertyChangedEventHandler::PropertyChangedEventHandler(O* object, M method) :
    PropertyChangedEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
{}

template <typename O, typename M> PropertyChangedEventHandler::PropertyChangedEventHandler(com_ptr<O>&& object, M method) :
    PropertyChangedEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
{}

template <typename O, typename M> PropertyChangedEventHandler::PropertyChangedEventHandler(weak_ref<O>&& object, M method) :
    PropertyChangedEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
{}

inline void PropertyChangedEventHandler::operator()(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::Data::PropertyChangedEventArgs const& e) const
{
    check_hresult((*(impl::abi_t<PropertyChangedEventHandler>**)this)->Invoke(get_abi(sender), get_abi(e)));
}

template <typename D, typename... Interfaces>
struct BindingT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Data::IBinding, Windows::UI::Xaml::Data::IBinding2, Windows::UI::Xaml::Data::IBindingBase, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Data::Binding, Windows::UI::Xaml::Data::BindingBase, Windows::UI::Xaml::DependencyObject>
{
    using composable = Binding;

protected:
    BindingT()
    {
        impl::call_factory<Windows::UI::Xaml::Data::Binding, Windows::UI::Xaml::Data::IBindingFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct BindingBaseT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Data::IBindingBase, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Data::BindingBase, Windows::UI::Xaml::DependencyObject>
{
    using composable = BindingBase;

protected:
    BindingBaseT()
    {
        impl::call_factory<Windows::UI::Xaml::Data::BindingBase, Windows::UI::Xaml::Data::IBindingBaseFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct CurrentChangingEventArgsT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Data::ICurrentChangingEventArgs>,
    impl::base<D, Windows::UI::Xaml::Data::CurrentChangingEventArgs>
{
    using composable = CurrentChangingEventArgs;

protected:
    CurrentChangingEventArgsT()
    {
        impl::call_factory<Windows::UI::Xaml::Data::CurrentChangingEventArgs, Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
    CurrentChangingEventArgsT(bool isCancelable)
    {
        impl::call_factory<Windows::UI::Xaml::Data::CurrentChangingEventArgs, Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory>([&](auto&& f) { f.CreateWithCancelableParameter(isCancelable, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct ItemIndexRangeT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Data::IItemIndexRange>,
    impl::base<D, Windows::UI::Xaml::Data::ItemIndexRange>
{
    using composable = ItemIndexRange;

protected:
    ItemIndexRangeT(int32_t firstIndex, uint32_t length)
    {
        impl::call_factory<Windows::UI::Xaml::Data::ItemIndexRange, Windows::UI::Xaml::Data::IItemIndexRangeFactory>([&](auto&& f) { f.CreateInstance(firstIndex, length, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct PropertyChangedEventArgsT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Data::IPropertyChangedEventArgs>,
    impl::base<D, Windows::UI::Xaml::Data::PropertyChangedEventArgs>
{
    using composable = PropertyChangedEventArgs;

protected:
    PropertyChangedEventArgsT(param::hstring const& name)
    {
        impl::call_factory<Windows::UI::Xaml::Data::PropertyChangedEventArgs, Windows::UI::Xaml::Data::IPropertyChangedEventArgsFactory>([&](auto&& f) { f.CreateInstance(name, *this, this->m_inner); });
    }
};

template <typename D, typename... Interfaces>
struct RelativeSourceT :
    implements<D, Windows::Foundation::IInspectable, composing, Interfaces...>,
    impl::require<D, Windows::UI::Xaml::Data::IRelativeSource, Windows::UI::Xaml::IDependencyObject, Windows::UI::Xaml::IDependencyObject2>,
    impl::base<D, Windows::UI::Xaml::Data::RelativeSource, Windows::UI::Xaml::DependencyObject>
{
    using composable = RelativeSource;

protected:
    RelativeSourceT()
    {
        impl::call_factory<Windows::UI::Xaml::Data::RelativeSource, Windows::UI::Xaml::Data::IRelativeSourceFactory>([&](auto&& f) { f.CreateInstance(*this, this->m_inner); });
    }
};

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Xaml::Data::IBinding> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IBinding> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IBinding2> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IBinding2> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IBindingBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IBindingBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingExpression> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IBindingExpression> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingExpressionBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IBindingExpressionBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingExpressionBaseFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IBindingExpressionBaseFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingExpressionFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IBindingExpressionFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IBindingFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingOperations> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IBindingOperations> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IBindingOperationsStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IBindingOperationsStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ICollectionView> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ICollectionView> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ICollectionViewFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ICollectionViewFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ICollectionViewGroup> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ICollectionViewGroup> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ICollectionViewSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ICollectionViewSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ICollectionViewSourceStatics> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ICollectionViewSourceStatics> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ICurrentChangingEventArgsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ICustomProperty> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ICustomProperty> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ICustomPropertyProvider> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ICustomPropertyProvider> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IItemIndexRange> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IItemIndexRange> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IItemIndexRangeFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IItemIndexRangeFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IItemsRangeInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IItemsRangeInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::INotifyPropertyChanged> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::INotifyPropertyChanged> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgsFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IPropertyChangedEventArgsFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IRelativeSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IRelativeSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IRelativeSourceFactory> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IRelativeSourceFactory> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ISelectionInfo> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ISelectionInfo> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ISupportIncrementalLoading> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ISupportIncrementalLoading> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::IValueConverter> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::IValueConverter> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::Binding> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::Binding> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::BindingBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::BindingBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::BindingExpression> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::BindingExpression> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::BindingExpressionBase> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::BindingExpressionBase> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::BindingOperations> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::BindingOperations> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::CollectionViewSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::CollectionViewSource> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::CurrentChangingEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::CurrentChangingEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::ItemIndexRange> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::ItemIndexRange> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::PropertyChangedEventArgs> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::PropertyChangedEventArgs> {};
template<> struct hash<winrt::Windows::UI::Xaml::Data::RelativeSource> : winrt::impl::hash_base<winrt::Windows::UI::Xaml::Data::RelativeSource> {};

}
