#include "pch.h"
#include "ResultsModel.h"

#include "AppPaths.h"
#include "DebugTrace.h"
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

// Rows stream in during a scan. With a sort active, only the new rows are sorted;
// they are then placed into the sorted view instead of re-filtering and
// re-sorting every row. A few new rows (the usual batch) each go in by binary
// search: about log n comparisons each. A large batch is merged in one pass.
// Both ways are stable and every new model index is larger than every old one,
// so ties come out in the same order a full Rebuild() would give.
void ResultsModel::Append(const std::vector<ScanRow>& rows)
{
    size_t first = m_rows.size();
    m_rows.insert(m_rows.end(), rows.begin(), rows.end());
    size_t oldViewSize = m_view.size();
    for (size_t i = first; i < m_rows.size(); ++i) {
        if (Visible(m_rows[i])) m_view.push_back(i);
    }
    if (!m_hasSort || m_view.size() == oldViewSize) return;

    auto less = [this](size_t a, size_t b) { return Less(a, b); };
    auto middle = m_view.begin() + static_cast<std::ptrdiff_t>(oldViewSize);
    std::stable_sort(middle, m_view.end(), less);

    size_t added = m_view.size() - oldViewSize;
    size_t log2n = 1;
    while (log2n < 63 && (static_cast<size_t>(1) << log2n) <= oldViewSize) ++log2n;
    if (added * log2n * 4 < oldViewSize) {
        std::vector<size_t> fresh(middle, m_view.end());
        m_view.resize(oldViewSize);
        for (size_t index : fresh) {
            m_view.insert(std::upper_bound(m_view.begin(), m_view.end(), index, less), index);
        }
        Trace(L"ResultsModel", L"Append inserted " + std::to_wstring(added) + L" sorted row(s) into " +
              std::to_wstring(oldViewSize));
        return;
    }
    std::inplace_merge(m_view.begin(), middle, m_view.end(), less);
    Trace(L"ResultsModel", L"Append merged " + std::to_wstring(added) + L" sorted row(s) into " +
          std::to_wstring(oldViewSize));
}

bool ResultsModel::ModelIndexOfView(size_t viewIndex, size_t& modelIndex) const
{
    if (viewIndex >= m_view.size()) {
        Trace(L"ResultsModel", L"ModelIndexOfView: view row " + std::to_wstring(viewIndex) + L" out of range");
        return false;
    }
    modelIndex = m_view[viewIndex];
    return true;
}

int ResultsModel::ViewIndexOfModel(size_t modelIndex) const
{
    for (size_t i = 0; i < m_view.size(); ++i) {
        if (m_view[i] == modelIndex) return static_cast<int>(i);
    }
    Trace(L"ResultsModel", L"ViewIndexOfModel: row " + std::to_wstring(modelIndex) + L" is not in the view");
    return -1;
}

// Type-ahead in the list: the first row at or after start whose file name begins
// with text (or equals it when exact), ignoring case. -1 when there is none.
int ResultsModel::FindByFileName(const std::wstring& text, size_t start, bool wrap, bool exact) const
{
    if (text.empty() || m_view.empty()) return -1;
    size_t count = m_view.size();
    if (start >= count) start = wrap ? 0 : count;
    size_t steps = wrap ? count : count - start;
    for (size_t n = 0; n < steps; ++n) {
        size_t viewIndex = (start + n) % count;
        std::wstring name = CellTextFor(m_rows[m_view[viewIndex]], ResultColumn::File);
        bool match = exact ? EqualsI(name, text) : StartsWithI(name, text);
        if (match) {
            Trace(L"ResultsModel", L"FindByFileName \"" + text + L"\" -> row " + std::to_wstring(viewIndex));
            return static_cast<int>(viewIndex);
        }
    }
    Trace(L"ResultsModel", L"FindByFileName \"" + text + L"\": no match");
    return -1;
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

// Strict weak order of two model rows under the current sort column and direction.
bool ResultsModel::Less(size_t a, size_t b) const
{
    const ScanRow& ra = m_rows[a];
    const ScanRow& rb = m_rows[b];
    int cmp = 0;
    if (m_sortColumn == ResultColumn::Score) {
        cmp = ra.entry.malwareScore < rb.entry.malwareScore ? -1 : (ra.entry.malwareScore > rb.entry.malwareScore ? 1 : 0);
    }
    else if (m_sortColumn == ResultColumn::Size) {
        cmp = ra.entry.fileSize < rb.entry.fileSize ? -1 : (ra.entry.fileSize > rb.entry.fileSize ? 1 : 0);
    }
    else if (m_sortColumn == ResultColumn::Version) {
        cmp = CompareVersions(ra.entry.version, rb.entry.version);
    }
    else {
        cmp = _wcsicmp(CellTextFor(ra, m_sortColumn).c_str(), CellTextFor(rb, m_sortColumn).c_str());
    }
    return m_ascending ? cmp < 0 : cmp > 0;
}

void ResultsModel::ApplySort()
{
    std::stable_sort(m_view.begin(), m_view.end(), [this](size_t a, size_t b) { return Less(a, b); });
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
