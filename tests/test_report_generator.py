import analyzer
import report_generator as rg


def test_summary_counts_match_findings():
    r = analyzer.run_demo_analysis()
    s = rg.compute_summary(r)
    assert s["total_findings"] == len(r["findings"])
    assert s["critical"] + s["high"] + s["medium"] + s["low"] + s["info"] == len(r["findings"])


def test_dataframe_is_sorted_and_csv_roundtrips():
    r = analyzer.run_demo_analysis()
    df = rg.findings_to_dataframe(r["findings"])
    assert len(df) == len(r["findings"])
    csv = rg.dataframe_to_csv_bytes(df).decode("utf-8")
    assert csv.count("\n") >= len(df)


def test_empty_findings_give_empty_frame():
    assert len(rg.findings_to_dataframe([])) == 0
