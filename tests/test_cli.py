import json

import gambit.__main__ as cli
from gambit.models import Severity
from gambit.modules import gather, takeover


def test_takeover_runs_per_host_not_only_on_apex():
    # Regression: takeover used to be apex-only, so a dangling CNAME on a
    # discovered subdomain (the README's own example) was never checked.
    assert takeover in cli.PER_HOST_MODULES
    assert takeover not in cli.APEX_MODULES
    assert cli.APEX_MODULES == [gather]


def test_preflight_gates_only_web_modules():
    # Takeover and ports must run even on hosts with no answering web
    # port: a dangling CNAME / open database port lives exactly there.
    from gambit.modules import ports

    assert set(cli.INFRA_MODULES) == {takeover, ports}
    assert takeover not in cli.WEB_MODULES
    assert ports not in cli.WEB_MODULES
    assert set(cli.PER_HOST_MODULES) == set(cli.WEB_MODULES) | set(cli.INFRA_MODULES)


def test_parser_defaults():
    args = cli.build_parser().parse_args(["example.com"])
    assert args.format == "text"
    assert args.json is False
    assert args.max_hosts == 25
    assert args.yes is False
    assert args.output is None
    assert args.insecure is False


def test_insecure_flag_is_opt_in():
    args = cli.build_parser().parse_args(["example.com", "--insecure"])
    assert args.insecure is True
    help_text = cli.build_parser().format_help()
    assert "--insecure" in help_text
    assert "plain HTTP" in help_text


def test_insecure_report_notes_that_verification_was_disabled():
    finding = cli.verification_disabled_finding("example.com")
    assert finding.severity == Severity.INFO
    assert "verification disabled" in finding.title.lower()
    text = cli.format_report([finding], "text", insecure=True)
    assert text.startswith("NOTE:")
    assert "--insecure" in text
    assert "not retried" in text
    markdown = cli.format_report([finding], "md", insecure=True)
    assert markdown.startswith("> NOTE:")
    payload = json.loads(cli.format_report([finding], "json", insecure=True))
    assert payload[0]["title"] == finding.title
    assert "plain HTTP" in payload[0]["evidence"]


def test_main_prints_insecure_note(monkeypatch, capsys):
    monkeypatch.setattr(cli, "collect_findings", lambda *args, **kwargs: [])
    code = cli.main(["example.com", "--yes", "--insecure"])
    captured = capsys.readouterr()
    assert code == 0
    assert "--insecure" in captured.err
    assert "verification was disabled" in captured.err
    assert "NOTE:" in captured.out


def test_json_flag_is_kept_as_alias():
    args = cli.build_parser().parse_args(["example.com", "--json"])
    assert args.json is True


def test_main_eof_on_prompt_is_quiet(monkeypatch, capsys):
    def boom(_prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", boom)

    def should_not_run(*_args, **_kwargs):
        raise AssertionError("scan should not start without authorization")

    monkeypatch.setattr(cli, "collect_findings", should_not_run)
    assert cli.main(["example.com"]) == 1
    captured = capsys.readouterr()
    assert "authorization not confirmed" in captured.err
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out


def test_main_ctrl_c_on_prompt_is_quiet(monkeypatch, capsys):
    def boom(_prompt=""):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", boom)
    monkeypatch.setattr(
        cli,
        "collect_findings",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("scan should not start")
        ),
    )
    assert cli.main(["example.com"]) == 1
    captured = capsys.readouterr()
    assert "authorization not confirmed" in captured.err
    assert "Traceback" not in captured.err


def test_main_ctrl_c_during_scan_is_quiet(monkeypatch, capsys):
    def boom(*_args, **_kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "collect_findings", boom)
    assert cli.main(["example.com", "--yes"]) == 1
    captured = capsys.readouterr()
    assert "Scan interrupted." in captured.err
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out
