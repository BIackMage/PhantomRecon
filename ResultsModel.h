#pragma once

#include <string>
#include <vector>
#include "ScanTypes.h"

// ---------------------------------------------------------------------------
// ResultsModel: the rows behind the results list, with filter, search and
// sort. Pure data: the list view asks it for cell text by view row and column.
// ---------------------------------------------------------------------------

enum class ResultColumn {
    File = 0, Status, Score, Signature, Packing, Size, Developer, Version, Attack, Sha256, Path, Count
};

enum class StatusFilter {
    All = 0, NeedsReview, NewOnly, ChangedOnly, MissingOnly, HighScore, MediumScore
};

class ResultsModel {
public:
    void Clear();
    void Append(const std::vector<ScanRow>& rows);
    void SetRows(std::vector<ScanRow> rows);

    void SetFilter(StatusFilter filter);
    void SetSearch(const std::wstring& text);
    // Clicking the same column again reverses the order.
    void SortBy(ResultColumn column);
    void SortBy(ResultColumn column, bool ascending);

    size_t TotalCount() const { return m_rows.size(); }
    size_t ViewCount() const { return m_view.size(); }
    const ScanRow& ViewRow(size_t viewIndex) const { return m_rows[m_view[viewIndex]]; }
    const std::vector<ScanRow>& AllRows() const { return m_rows; }
    std::vector<ScanRow> VisibleRows() const;

    std::wstring CellText(size_t viewIndex, ResultColumn column) const;

    ResultColumn SortColumn() const { return m_sortColumn; }
    bool SortAscending() const { return m_ascending; }
    bool HasSort() const { return m_hasSort; }
    StatusFilter Filter() const { return m_filter; }

    static const wchar_t* ColumnName(ResultColumn column);
    static int ColumnWidth(ResultColumn column);
    static std::wstring CellTextFor(const ScanRow& row, ResultColumn column);
    static bool PassesFilter(const ScanRow& row, StatusFilter filter);

private:
    std::vector<ScanRow> m_rows;
    std::vector<size_t>  m_view;
    StatusFilter         m_filter = StatusFilter::All;
    std::wstring         m_searchLower;
    ResultColumn         m_sortColumn = ResultColumn::File;
    bool                 m_ascending = true;
    bool                 m_hasSort = false;

    bool Visible(const ScanRow& row) const;
    void Rebuild();
    void ApplySort();
};
