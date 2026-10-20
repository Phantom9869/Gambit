import gambit.__main__ as cli
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


def test_json_flag_is_kept_as_alias():
    args = cli.build_parser().parse_args(["example.com", "--json"])
    assert args.json is True
