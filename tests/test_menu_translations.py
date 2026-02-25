import importlib

vanta = importlib.import_module("vanta")

def test_translation_key_parity():
    en = vanta.TRANSLATIONS["EN"]
    fr = vanta.TRANSLATIONS["FR"]
    assert set(en.keys()) == set(fr.keys())

def test_required_keys_present():
    for lang in ("EN", "FR"):
        d = vanta.TRANSLATIONS[lang]
        for key in [
            "menu_title","menu_options","prompt","features_header","features",
            "starting_services","services_started","api_docs_opened","config_header",
            "logs_header","logs_missing","switch_lang","ghost_triggered","enter_url",
            "report_generated","invalid_option","stopping_services","services_stopped",
            "health_check","health_ok","health_fail","enter_phishlet","starting_proxy",
            "proxy_started","enter_platform","enter_type","running_templates","templates_done",
            "running_phishlets","phishlets_done","auto_setup","setup_done","system_info_header",
            "os_name","os_version","python_version","node_version","cpu_cores","mem_total"
            ,"godmode_start","godmode_done"
        ]:
            assert key in d
