import glob
import os

import pytest
import yaml


OLD_FORMAT_REQUIRED_FIELDS: tuple[str, ...] = (
    "min_ver",
    "proxy_hosts",
    "login",
)


def phishlet_files() -> list[str]:
    base = os.path.join(os.getcwd(), "phishlets")
    return sorted(glob.glob(os.path.join(base, "*.yaml")))


def _is_advanced_v2(filename: str, data: dict) -> bool:
    """Retourne True si le fichier est au format Vantablack V2 (`*_advanced.yaml`).

    Critères (fiables, ordonnés par spécificité) :
      1. suffixe de fichier : termine par `_advanced.yaml`
      2. OU absence totale de `min_ver` (champ obligatoire en legacy V1)
         ET présence à la racine d'au moins 2 champs parmi name / description
         / base_domain / target_url / credentials.
    """
    basename = os.path.basename(filename)
    if basename.endswith("_advanced.yaml"):
        return True
    if "min_ver" in data:
        return False
    v2_markers = {"name", "description", "base_domain", "target_url", "credentials"}
    return len(v2_markers & set(data.keys())) >= 2


@pytest.mark.parametrize("path", phishlet_files())
def test_phishlet_yaml_valid(path: str) -> None:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    assert isinstance(data, dict), (
        f"{path}: contenu YAML invalide, dict attendu"
    )

    is_advanced_v2 = _is_advanced_v2(path, data)

    if is_advanced_v2:
        # Format Vantablack v2 — schema étendu (proxy AiTM pro)
        basename = os.path.basename(path)
        has_legacy_mfa = ("mfa" in data) and isinstance(data.get("mfa"), dict)
        has_pattern_mfa = (
            ("mfa_patterns" in data)
            and isinstance(data.get("mfa_patterns"), dict)
        )

        # Champs obligatoires du format V2 (les 4 `*_advanced.yaml` ont cela)
        if basename in {"office365_advanced.yaml", "facebook_advanced.yaml",
                        "gmail_advanced.yaml"}:
            for mandatory in ("name", "description", "base_domain",
                              "target_url", "credentials"):
                assert mandatory in data, (
                    f"{path}: champ '{mandatory}' attendu (format V2)"
                )
            creds = data["credentials"]
            assert isinstance(creds, dict), (
                f"{path}: credentials doit être un dict (format V2)"
            )
            for k in ("username_selector", "password_selector", "submit_selector"):
                assert k in creds, (
                    f"{path}: credentials.{k} attendu format V2"
                )
            if has_legacy_mfa and data["mfa"].get("enabled"):
                mfa = data["mfa"]
                for k in ("sms_code_pattern", "email_code_pattern",
                          "app_code_selector"):
                    assert k in mfa, (
                        f"{path}: mfa.{k} attendu si MFA enabled (V2)"
                    )
        elif basename == "advanced_office365.yaml":
            # Cas particulier : hybrid legacy/V2 avec sections mfa_patterns /
            # advanced / auth_tokens / opsec (pas min_ver, pas login non plus)
            for mandatory in ("auth_tokens", "mfa_patterns"):
                assert mandatory in data, (
                    f"{path}: champ '{mandatory}' attendu (advanced_office365)"
                )
            assert isinstance(data["mfa_patterns"], dict)
            assert "sms" in data["mfa_patterns"] or "email" in data["mfa_patterns"]
        # (Autres cas ? Rien d'autre en suffixe _advanced pour l'instant)
    else:
        # Format legacy Evilginx — validation stricte historique
        for field in OLD_FORMAT_REQUIRED_FIELDS:
            assert field in data, (
                f"{path}: champ '{field}' attendu (format legacy/Evilginx-like)"
            )
        assert isinstance(data["proxy_hosts"], list), (
            f"{path}: proxy_hosts doit être une liste"
        )
        login = data["login"]
        assert isinstance(login, dict), (
            f"{path}: 'login' doit être un dict (legacy)"
        )
        assert "domain" in login, f"{path}: login.domain attendu"
        assert "path" in login, f"{path}: login.path attendu"
