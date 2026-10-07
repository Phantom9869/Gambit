from gambit.models import Finding, Severity

def test_severity_ordering():
    assert Severity.HIGH > Severity.MED

def test_to_dict_uses_severity_name():
    f = Finding(Severity.HIGH, "example.com", "t", "e", "w", "n")
    assert f.to_dict()["severity"] == "HIGH"