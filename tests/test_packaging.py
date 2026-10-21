from pathlib import Path


def test_runtime_dependencies_are_pinned_and_ci_audits_them():
    root = Path(__file__).resolve().parents[1]
    project = (root / "pyproject.toml").read_text(encoding="utf-8")
    requirements = (root / "requirements.txt").read_text(encoding="utf-8")
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for pin in ("dnspython==2.8.0", "requests==2.34.2", "urllib3==2.8.0"):
        assert pin in project
        assert pin in requirements
    assert "pip_audit" in workflow or "pip-audit" in workflow
    assert "requirements.txt" in workflow
