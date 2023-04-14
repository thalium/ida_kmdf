// C++/WinRT v1.0.190111.3

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include "winrt/base.h"

#include "winrt/Windows.Foundation.h"
#include "winrt/Windows.Foundation.Collections.h"
#include "winrt/impl/Windows.UI.Input.Inking.2.h"
#include "winrt/impl/Windows.UI.Input.Inking.Analysis.2.h"
#include "winrt/Windows.UI.Input.Inking.h"

namespace winrt::impl {

template <typename D> hstring consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkBullet<D>::RecognizedText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisInkBullet)->get_RecognizedText(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::Analysis::InkAnalysisDrawingKind consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkDrawing<D>::DrawingKind() const
{
    Windows::UI::Input::Inking::Analysis::InkAnalysisDrawingKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing)->get_DrawingKind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Point consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkDrawing<D>::Center() const
{
    Windows::Foundation::Point value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing)->get_Center(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Foundation::Point> consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkDrawing<D>::Points() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Foundation::Point> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing)->get_Points(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkWord<D>::RecognizedText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord)->get_RecognizedText(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<hstring> consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisInkWord<D>::TextAlternates() const
{
    Windows::Foundation::Collections::IVectorView<hstring> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord)->get_TextAlternates(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisLine<D>::RecognizedText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisLine)->get_RecognizedText(put_abi(value)));
    return value;
}

template <typename D> int32_t consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisLine<D>::IndentLevel() const
{
    int32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisLine)->get_IndentLevel(&value));
    return value;
}

template <typename D> hstring consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisListItem<D>::RecognizedText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisListItem)->get_RecognizedText(put_abi(value)));
    return value;
}

template <typename D> uint32_t consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::Id() const
{
    uint32_t value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_Id(&value));
    return value;
}

template <typename D> Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::Kind() const
{
    Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_Kind(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Rect consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::BoundingRect() const
{
    Windows::Foundation::Rect value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_BoundingRect(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::Foundation::Point> consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::RotatedBoundingRect() const
{
    Windows::Foundation::Collections::IVectorView<Windows::Foundation::Point> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_RotatedBoundingRect(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::Analysis::IInkAnalysisNode> consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::Children() const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::Analysis::IInkAnalysisNode> value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_Children(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::Analysis::IInkAnalysisNode consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::Parent() const
{
    Windows::UI::Input::Inking::Analysis::IInkAnalysisNode value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->get_Parent(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<uint32_t> consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisNode<D>::GetStrokeIds() const
{
    Windows::Foundation::Collections::IVectorView<uint32_t> strokeIds{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisNode)->GetStrokeIds(put_abi(strokeIds)));
    return strokeIds;
}

template <typename D> hstring consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisParagraph<D>::RecognizedText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisParagraph)->get_RecognizedText(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::Analysis::InkAnalysisStatus consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisResult<D>::Status() const
{
    Windows::UI::Input::Inking::Analysis::InkAnalysisStatus value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisResult)->get_Status(put_abi(value)));
    return value;
}

template <typename D> hstring consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisRoot<D>::RecognizedText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot)->get_RecognizedText(put_abi(value)));
    return value;
}

template <typename D> Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::Analysis::IInkAnalysisNode> consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisRoot<D>::FindNodes(Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind const& nodeKind) const
{
    Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::Analysis::IInkAnalysisNode> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot)->FindNodes(get_abi(nodeKind), put_abi(result)));
    return result;
}

template <typename D> hstring consume_Windows_UI_Input_Inking_Analysis_IInkAnalysisWritingRegion<D>::RecognizedText() const
{
    hstring value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalysisWritingRegion)->get_RecognizedText(put_abi(value)));
    return value;
}

template <typename D> Windows::UI::Input::Inking::Analysis::InkAnalysisRoot consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::AnalysisRoot() const
{
    Windows::UI::Input::Inking::Analysis::InkAnalysisRoot value{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->get_AnalysisRoot(put_abi(value)));
    return value;
}

template <typename D> bool consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::IsAnalyzing() const
{
    bool value{};
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->get_IsAnalyzing(&value));
    return value;
}

template <typename D> void consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::AddDataForStroke(Windows::UI::Input::Inking::InkStroke const& stroke) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->AddDataForStroke(get_abi(stroke)));
}

template <typename D> void consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::AddDataForStrokes(param::iterable<Windows::UI::Input::Inking::InkStroke> const& strokes) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->AddDataForStrokes(get_abi(strokes)));
}

template <typename D> void consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::ClearDataForAllStrokes() const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->ClearDataForAllStrokes());
}

template <typename D> void consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::RemoveDataForStroke(uint32_t strokeId) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->RemoveDataForStroke(strokeId));
}

template <typename D> void consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::RemoveDataForStrokes(param::iterable<uint32_t> const& strokeIds) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->RemoveDataForStrokes(get_abi(strokeIds)));
}

template <typename D> void consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::ReplaceDataForStroke(Windows::UI::Input::Inking::InkStroke const& stroke) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->ReplaceDataForStroke(get_abi(stroke)));
}

template <typename D> void consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::SetStrokeDataKind(uint32_t strokeId, Windows::UI::Input::Inking::Analysis::InkAnalysisStrokeKind const& strokeKind) const
{
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->SetStrokeDataKind(strokeId, get_abi(strokeKind)));
}

template <typename D> Windows::Foundation::IAsyncOperation<Windows::UI::Input::Inking::Analysis::InkAnalysisResult> consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzer<D>::AnalyzeAsync() const
{
    Windows::Foundation::IAsyncOperation<Windows::UI::Input::Inking::Analysis::InkAnalysisResult> result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalyzer)->AnalyzeAsync(put_abi(result)));
    return result;
}

template <typename D> Windows::UI::Input::Inking::Analysis::InkAnalyzer consume_Windows_UI_Input_Inking_Analysis_IInkAnalyzerFactory<D>::CreateAnalyzer() const
{
    Windows::UI::Input::Inking::Analysis::InkAnalyzer result{ nullptr };
    check_hresult(WINRT_SHIM(Windows::UI::Input::Inking::Analysis::IInkAnalyzerFactory)->CreateAnalyzer(put_abi(result)));
    return result;
}

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisInkBullet> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisInkBullet>
{
    int32_t WINRT_CALL get_RecognizedText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognizedText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing>
{
    int32_t WINRT_CALL get_DrawingKind(Windows::UI::Input::Inking::Analysis::InkAnalysisDrawingKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(DrawingKind, WINRT_WRAP(Windows::UI::Input::Inking::Analysis::InkAnalysisDrawingKind));
            *value = detach_from<Windows::UI::Input::Inking::Analysis::InkAnalysisDrawingKind>(this->shim().DrawingKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Center(Windows::Foundation::Point* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Center, WINRT_WRAP(Windows::Foundation::Point));
            *value = detach_from<Windows::Foundation::Point>(this->shim().Center());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Points(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Points, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Foundation::Point>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Point>>(this->shim().Points());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord>
{
    int32_t WINRT_CALL get_RecognizedText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognizedText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_TextAlternates(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(TextAlternates, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<hstring>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().TextAlternates());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisLine> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisLine>
{
    int32_t WINRT_CALL get_RecognizedText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognizedText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IndentLevel(int32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IndentLevel, WINRT_WRAP(int32_t));
            *value = detach_from<int32_t>(this->shim().IndentLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisListItem> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisListItem>
{
    int32_t WINRT_CALL get_RecognizedText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognizedText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisNode> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>
{
    int32_t WINRT_CALL get_Id(uint32_t* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Id, WINRT_WRAP(uint32_t));
            *value = detach_from<uint32_t>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Kind(Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Kind, WINRT_WRAP(Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind));
            *value = detach_from<Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_BoundingRect(Windows::Foundation::Rect* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(BoundingRect, WINRT_WRAP(Windows::Foundation::Rect));
            *value = detach_from<Windows::Foundation::Rect>(this->shim().BoundingRect());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_RotatedBoundingRect(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RotatedBoundingRect, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::Foundation::Point>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::Foundation::Point>>(this->shim().RotatedBoundingRect());
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
            WINRT_ASSERT_DECLARATION(Children, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>));
            *value = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>>(this->shim().Children());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_Parent(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Parent, WINRT_WRAP(Windows::UI::Input::Inking::Analysis::IInkAnalysisNode));
            *value = detach_from<Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>(this->shim().Parent());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL GetStrokeIds(void** strokeIds) noexcept final
    {
        try
        {
            *strokeIds = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(GetStrokeIds, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<uint32_t>));
            *strokeIds = detach_from<Windows::Foundation::Collections::IVectorView<uint32_t>>(this->shim().GetStrokeIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisParagraph> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisParagraph>
{
    int32_t WINRT_CALL get_RecognizedText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognizedText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisResult> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisResult>
{
    int32_t WINRT_CALL get_Status(Windows::UI::Input::Inking::Analysis::InkAnalysisStatus* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(Status, WINRT_WRAP(Windows::UI::Input::Inking::Analysis::InkAnalysisStatus));
            *value = detach_from<Windows::UI::Input::Inking::Analysis::InkAnalysisStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot>
{
    int32_t WINRT_CALL get_RecognizedText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognizedText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL FindNodes(Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind nodeKind, void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(FindNodes, WINRT_WRAP(Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>), Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind const&);
            *result = detach_from<Windows::Foundation::Collections::IVectorView<Windows::UI::Input::Inking::Analysis::IInkAnalysisNode>>(this->shim().FindNodes(*reinterpret_cast<Windows::UI::Input::Inking::Analysis::InkAnalysisNodeKind const*>(&nodeKind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisWritingRegion> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalysisWritingRegion>
{
    int32_t WINRT_CALL get_RecognizedText(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RecognizedText, WINRT_WRAP(hstring));
            *value = detach_from<hstring>(this->shim().RecognizedText());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalyzer> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalyzer>
{
    int32_t WINRT_CALL get_AnalysisRoot(void** value) noexcept final
    {
        try
        {
            *value = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnalysisRoot, WINRT_WRAP(Windows::UI::Input::Inking::Analysis::InkAnalysisRoot));
            *value = detach_from<Windows::UI::Input::Inking::Analysis::InkAnalysisRoot>(this->shim().AnalysisRoot());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL get_IsAnalyzing(bool* value) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(IsAnalyzing, WINRT_WRAP(bool));
            *value = detach_from<bool>(this->shim().IsAnalyzing());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddDataForStroke(void* stroke) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddDataForStroke, WINRT_WRAP(void), Windows::UI::Input::Inking::InkStroke const&);
            this->shim().AddDataForStroke(*reinterpret_cast<Windows::UI::Input::Inking::InkStroke const*>(&stroke));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AddDataForStrokes(void* strokes) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AddDataForStrokes, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<Windows::UI::Input::Inking::InkStroke> const&);
            this->shim().AddDataForStrokes(*reinterpret_cast<Windows::Foundation::Collections::IIterable<Windows::UI::Input::Inking::InkStroke> const*>(&strokes));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ClearDataForAllStrokes() noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ClearDataForAllStrokes, WINRT_WRAP(void));
            this->shim().ClearDataForAllStrokes();
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveDataForStroke(uint32_t strokeId) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveDataForStroke, WINRT_WRAP(void), uint32_t);
            this->shim().RemoveDataForStroke(strokeId);
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL RemoveDataForStrokes(void* strokeIds) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(RemoveDataForStrokes, WINRT_WRAP(void), Windows::Foundation::Collections::IIterable<uint32_t> const&);
            this->shim().RemoveDataForStrokes(*reinterpret_cast<Windows::Foundation::Collections::IIterable<uint32_t> const*>(&strokeIds));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL ReplaceDataForStroke(void* stroke) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(ReplaceDataForStroke, WINRT_WRAP(void), Windows::UI::Input::Inking::InkStroke const&);
            this->shim().ReplaceDataForStroke(*reinterpret_cast<Windows::UI::Input::Inking::InkStroke const*>(&stroke));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL SetStrokeDataKind(uint32_t strokeId, Windows::UI::Input::Inking::Analysis::InkAnalysisStrokeKind strokeKind) noexcept final
    {
        try
        {
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(SetStrokeDataKind, WINRT_WRAP(void), uint32_t, Windows::UI::Input::Inking::Analysis::InkAnalysisStrokeKind const&);
            this->shim().SetStrokeDataKind(strokeId, *reinterpret_cast<Windows::UI::Input::Inking::Analysis::InkAnalysisStrokeKind const*>(&strokeKind));
            return 0;
        }
        catch (...) { return to_hresult(); }
    }

    int32_t WINRT_CALL AnalyzeAsync(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(AnalyzeAsync, WINRT_WRAP(Windows::Foundation::IAsyncOperation<Windows::UI::Input::Inking::Analysis::InkAnalysisResult>));
            *result = detach_from<Windows::Foundation::IAsyncOperation<Windows::UI::Input::Inking::Analysis::InkAnalysisResult>>(this->shim().AnalyzeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

template <typename D>
struct produce<D, Windows::UI::Input::Inking::Analysis::IInkAnalyzerFactory> : produce_base<D, Windows::UI::Input::Inking::Analysis::IInkAnalyzerFactory>
{
    int32_t WINRT_CALL CreateAnalyzer(void** result) noexcept final
    {
        try
        {
            *result = nullptr;
            typename D::abi_guard guard(this->shim());
            WINRT_ASSERT_DECLARATION(CreateAnalyzer, WINRT_WRAP(Windows::UI::Input::Inking::Analysis::InkAnalyzer));
            *result = detach_from<Windows::UI::Input::Inking::Analysis::InkAnalyzer>(this->shim().CreateAnalyzer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    }
};

}

WINRT_EXPORT namespace winrt::Windows::UI::Input::Inking::Analysis {

inline InkAnalyzer::InkAnalyzer() :
    InkAnalyzer(impl::call_factory<InkAnalyzer>([](auto&& f) { return f.template ActivateInstance<InkAnalyzer>(); }))
{}

}

WINRT_EXPORT namespace std {

template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkBullet> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkBullet> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkDrawing> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisInkWord> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisLine> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisLine> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisListItem> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisListItem> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisNode> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisParagraph> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisParagraph> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisResult> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisResult> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisRoot> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisWritingRegion> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalysisWritingRegion> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzer> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzerFactory> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::IInkAnalyzerFactory> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisInkBullet> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisInkBullet> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisInkDrawing> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisInkDrawing> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisInkWord> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisInkWord> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisLine> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisLine> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisListItem> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisListItem> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisNode> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisNode> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisParagraph> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisParagraph> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisResult> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisResult> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisRoot> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisRoot> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisWritingRegion> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::InkAnalysisWritingRegion> {};
template<> struct hash<winrt::Windows::UI::Input::Inking::Analysis::InkAnalyzer> : winrt::impl::hash_base<winrt::Windows::UI::Input::Inking::Analysis::InkAnalyzer> {};

}
