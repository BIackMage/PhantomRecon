#include "pch.h"
#include "ResultsModel.h"

#include "AppPaths.h"
#include "TextUtils.h"

#include <algorithm>

const wchar_t* ResultsModel::ColumnName(ResultColumn column)
{
    switch (column) {
    case ResultColumn::File:      return L"File";
    case ResultColumn::Status:    return L"Status";
    case ResultColumn::Score:     return L"Score";
    case ResultColumn::Signature: return L"Signature";
    case ResultColumn::Packing:   return L"Packing";
    case ResultColumn::Size:      return L"Size";
    case ResultColumn::Developer: return L"Developer";
    case ResultColumn::Version:   return L"Version";
    case ResultColumn::Attack:    return L"ATT&CK";
    case ResultColumn::Sha256:    return L"SHA-256";
    case ResultColumn::Path:      return L"Full path";
    default:                      return L"";
    }
}

int ResultsModel::ColumnWidth(ResultColumn column)
{
    switch (column) {
    case ResultColumn::File:      return 200;
    case ResultColumn::Status:    return 75;
    case ResultColumn::Score:     return 55;
    case ResultColumn::Signature: return 170;
    case ResultColumn::Packing:   return 100;
    case ResultColumn::Size:      return 70;
    case ResultColumn::Developer: return 130;
    case ResultColumn::Version:   return 90;
    case ResultColumn::Attack:    return 120;
    case ResultColumn::Sha256:    return 120;
    case ResultColumn::Path:      return 400;
    default:                      return 80;
    }
}

std::wstring ResultsModel::CellTextFor(const ScanRow& row, ResultColumn column)
{
    const BaselineEntry& e = row.entry;
    switch (column) {
    case ResultColumn::File:      return FileNameOf(e.path);
    case ResultColumn::Status:    return row.status;
    case ResultColumn::Score:     return FormatFixed(e.malwareScore, 1);
    case ResultColumn::Signature: return e.signature;
    case ResultColumn::Packing:   return e.packingStatus;
    case ResultColumn::Size:      return e.fileSize < 0 ? L"?" : std::to_wstring(e.fileSize / 1024) + L" KB";
    case ResultColumn::Developer: return e.developer;
    case ResultColumn::Version:   return e.version;
    case ResultColumn::Attack:    return e.attackIds;
    case ResultColumn::Sha256:    return e.sha256.size() > 16 ? e.sha256.substr(0, 16) + L"..." : e.sha256;
    case ResultColumn::Path:      return e.path;
    default:                      return L"";
    }
}

bool ResultsModel::PassesFilter(const ScanRow& row, StatusFilter filter)
{
    switch (filter) {
    case StatusFilter::All:         return true;
    case StatusFilter::NeedsReview: return row.status == L"NEW" || row.status == L"CHANGED" || row.status == L"MISSING" ||
                                           row.entry.malwareScore >= 7.0;
    case StatusFilter::NewOnly:     return row.status == L"NEW";
    case StatusFilter::ChangedOnly: return row.status == L"CHANGED";
    case StatusFilter::MissingOnly: return row.status == L"MISSING";
    case StatusFilter::HighScore:   return row.entry.malwareScore >= 7.0;
    case StatusFilter::MediumScore: return row.entry.malwareScore >= 4.0;
    default:                        return true;
    }
}

bool ResultsModel::Visible(const ScanRow& row) const
{
    if (!PassesFilter(row, m_filter)) return false;
    if (!m_searchLower.empty()) {
        if (ToLowerW(row.entry.path).find(m_searchLower) == std::wstring::npos &&
            ToLowerW(row.entry.signature).find(m_searchLower) == std::wstring::npos &&
            ToLowerW(row.entry.developer).find(m_searchLower) == std::wstring::npos &&
            ToLowerW(row.entry.sha256).find(m_searchLower) == std::wstring::npos) {
            return false;
        }
    }
    return true;
}

void ResultsModel::Clear()
{
    m_rows.clear();
    m_view.clear();
}

void ResultsModel::Append(const std::vector<ScanRow>& rows)
{
    size_t first = m_rows.size();
    m_rows.insert(m_rows.end(), rows.begin(), rows.end());
    if (m_hasSort) {
        Rebuild();
        return;
    }
    for (size_t i = first; i < m_rows.size(); ++i) {
        if (Visible(m_rows[i])) m_view.push_back(i);
    }
}

void ResultsModel::SetRows(std::vector<ScanRow> rows)
{
    m_rows = std::move(rows);
    Rebuild();
}

void ResultsModel::SetFilter(StatusFilter filter)
{
    m_filter = filter;
    Rebuild();
}

void ResultsModel::SetSearch(const std::wstring& text)
{
    m_searchLower = ToLowerW(TrimW(text));
    Rebuild();
}

void ResultsModel::SortBy(ResultColumn column)
{
    if (m_hasSort && m_sortColumn == column) {
        m_ascending = !m_ascending;
    }
    else {
        m_sortColumn = column;
        // Scores read best highest-first; everything else A to Z.
        m_ascending = column != ResultColumn::Score;
    }
    m_hasSort = true;
    ApplySort();
}

void ResultsModel::SortBy(ResultColumn column, bool ascending)
{
    m_sortColumn = column;
    m_ascending = ascending;
    m_hasSort = true;
    ApplySort();
}

void ResultsModel::Rebuild()
{
    m_view.clear();
    for (size_t i = 0; i < m_rows.size(); ++i) {
        if (Visible(m_rows[i])) m_view.push_back(i);
    }
    if (m_hasSort) ApplySort();
}

void ResultsModel::ApplySort()
{
    ResultColumn column = m_sortColumn;
    bool ascending = m_ascending;
    const std::vector<ScanRow>& rows = m_rows;
    std::stable_sort(m_view.begin(), m_view.end(), [&](size_t a, size_t b) {
        const ScanRow& ra = rows[a];
        const ScanRow& rb = rows[b];
        int cmp = 0;
        if (column == ResultColumn::Score) {
            cmp = ra.entry.malwareScore < rb.entry.malwareScore ? -1 : (ra.entry.malwareScore > rb.entry.malwareScore ? 1 : 0);
        }
        else if (column == ResultColumn::Size) {
            cmp = ra.entry.fileSize < rb.entry.fileSize ? -1 : (ra.entry.fileSize > rb.entry.fileSize ? 1 : 0);
        }
        else if (column == ResultColumn::Version) {
            cmp = CompareVersions(ra.entry.version, rb.entry.version);
        }
        else {
            cmp = _wcsicmp(CellTextFor(ra, column).c_str(), CellTextFor(rb, column).c_str());
        }
        return ascending ? cmp < 0 : cmp > 0;
    });
}

std::vector<ScanRow> ResultsModel::VisibleRows() const
{
    std::vector<ScanRow> out;
    out.reserve(m_view.size());
    for (size_t i : m_view) out.push_back(m_rows[i]);
    return out;
}

std::wstring ResultsModel::CellText(size_t viewIndex, ResultColumn column) const
{
    if (viewIndex >= m_view.size()) return L"";
    return CellTextFor(m_rows[m_view[viewIndex]], column);
}
