import json
import pytest
from patch_checker.detector import CVEResult, FIXED, VULNERABLE, NOT_MITIGATED, MITIGATED, MANUAL_CHECK_REQUIRED
from patch_checker.reporter import exit_code, format_json, format_text


def _make_result(cve_id="CVE-2026-31431", nickname="CopyFail",
                 mit=MITIGATED, perm=FIXED, action="対応不要", method="changelog_grep", notes=""):
    return CVEResult(
        cve_id=cve_id, nickname=nickname,
        mitigation_status=mit, permanent_fix_status=perm,
        recommended_action=action, detection_method=method, notes=notes,
    )


class TestFormatText:
    def test_contains_host_info(self):
        results = [_make_result()]
        text = format_text("myhost", "6.1.169", "ubuntu", results)
        assert "myhost" in text
        assert "6.1.169" in text
        assert "ubuntu" in text

    def test_contains_cve_id(self):
        results = [_make_result()]
        text = format_text("h", "6.1.169", "ubuntu", results)
        assert "CVE-2026-31431" in text

    def test_manual_check_required_shown(self):
        results = [_make_result(perm=MANUAL_CHECK_REQUIRED)]
        text = format_text("h", "6.1.169", "ubuntu", results)
        assert "MANUAL_CHECK_REQUIRED" in text

    def test_apply_results_shown(self):
        results = [_make_result()]
        apply_r = [{"success": True, "message": "algif_aead: アンロードしました。"}]
        text = format_text("h", "6.1.169", "ubuntu", results, apply_r)
        assert "アンロードしました" in text

    def test_notes_shown(self):
        results = [_make_result(notes="changelogが利用不可")]
        text = format_text("h", "6.1.169", "ubuntu", results)
        assert "changelogが利用不可" in text


class TestFormatJson:
    def test_valid_json(self):
        results = [_make_result()]
        out = format_json("h", "6.1.169", "ubuntu", results)
        data = json.loads(out)  # must not raise
        assert data["host"] == "h"
        assert data["kernel"] == "6.1.169"
        assert data["distro"] == "ubuntu"
        assert len(data["results"]) == 1

    def test_result_fields(self):
        results = [_make_result()]
        data = json.loads(format_json("h", "6.1.169", "ubuntu", results))
        r = data["results"][0]
        assert r["cve_id"] == "CVE-2026-31431"
        assert r["mitigation_status"] == MITIGATED
        assert r["permanent_fix_status"] == FIXED
        assert "recommended_action" in r
        assert "detection_method" in r

    def test_apply_results_included(self):
        results = [_make_result()]
        apply_r = [{"success": True, "message": "OK"}]
        data = json.loads(format_json("h", "6.1.169", "ubuntu", results, apply_r))
        assert "apply_results" in data

    def test_manual_check_cve(self):
        results = [_make_result(perm=MANUAL_CHECK_REQUIRED)]
        data = json.loads(format_json("h", "6.1.169", "ubuntu", results))
        assert data["results"][0]["permanent_fix_status"] == MANUAL_CHECK_REQUIRED


class TestExitCode:
    def test_all_fixed_exits_0(self):
        results = [_make_result(mit=MITIGATED, perm=FIXED)]
        assert exit_code(results) == 0

    def test_vulnerable_exits_1(self):
        results = [_make_result(perm=VULNERABLE)]
        assert exit_code(results) == 1

    def test_not_mitigated_exits_1(self):
        results = [_make_result(mit=NOT_MITIGATED, perm=FIXED)]
        assert exit_code(results) == 1

    def test_manual_check_with_mitigated_exits_0(self):
        results = [_make_result(mit=MITIGATED, perm=MANUAL_CHECK_REQUIRED)]
        assert exit_code(results) == 0

    def test_mixed_exits_1(self):
        results = [
            _make_result(mit=MITIGATED, perm=FIXED),
            _make_result(mit=NOT_MITIGATED, perm=VULNERABLE),
        ]
        assert exit_code(results) == 1
