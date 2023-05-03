
def test_yaml_local(bouncer, bm_cfg_factory):
    cfg = bm_cfg_factory()

    with bouncer(cfg) as bm:
        bm.wait_for_lines_fnmatch([
            "*one of lapi_key or cert_path is required*",
        ])
        bm.proc.wait(timeout=0.2)
        assert not bm.proc.is_running()

    config_local = {
        'crowdsec_config': {
            'lapi_key': 'not-used',
        }
    }

    with bouncer(cfg, config_local=config_local) as bm:
        bm.wait_for_lines_fnmatch([
            "*lapi_url is required*",
        ])
        bm.proc.wait(timeout=0.2)
        assert not bm.proc.is_running()

