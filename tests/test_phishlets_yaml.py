import os
import glob
import yaml
import pytest

def phishlet_files():
    base = os.path.join(os.getcwd(), "phishlets")
    return glob.glob(os.path.join(base, "*.yaml"))

@pytest.mark.parametrize("path", phishlet_files())
def test_phishlet_yaml_valid(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    assert isinstance(data, dict)
    assert "min_ver" in data
    assert "proxy_hosts" in data and isinstance(data["proxy_hosts"], list)
    assert "login" in data and isinstance(data["login"], dict)
    assert "domain" in data["login"]
    assert "path" in data["login"]
