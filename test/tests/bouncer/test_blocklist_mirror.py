
def test_no_api_key(crowdsec, bouncer, bm_cfg_factory):
    cfg = bm_cfg_factory()
    with bouncer(cfg) as bm:
        bm.wait_for_lines_fnmatch([
            "*one of lapi_key or cert_path is required*",
        ])
        bm.proc.wait(timeout=0.2)
        assert not bm.proc.is_running()

    cfg['crowdsec_config']['lapi_key'] = ''

    with bouncer(cfg) as bm:
        bm.wait_for_lines_fnmatch([
            "*one of lapi_key or cert_path is required*",
        ])
        bm.proc.wait(timeout=0.2)
        assert not bm.proc.is_running()


def test_no_lapi_url(bouncer, bm_cfg_factory):
    cfg = bm_cfg_factory()

    cfg['crowdsec_config']['lapi_key'] = 'not-used'

    with bouncer(cfg) as bm:
        bm.wait_for_lines_fnmatch([
            "*lapi_url is required*",
        ])
        bm.proc.wait(timeout=0.2)
        assert not bm.proc.is_running()

    cfg['crowdsec_config']['lapi_url'] = ''

    with bouncer(cfg) as bm:
        bm.wait_for_lines_fnmatch([
            "*lapi_url is required*",
        ])
        bm.proc.wait(timeout=0.2)
        assert not bm.proc.is_running()


def test_no_lapi(bouncer, bm_cfg_factory):
    cfg = bm_cfg_factory()
    cfg['crowdsec_config']['lapi_key'] = 'not-used'
    cfg['crowdsec_config']['lapi_url'] = 'http://localhost:8237'

    with bouncer(cfg) as bm:
        bm.wait_for_lines_fnmatch([
            "*connection refused*",
            "*terminating bouncer process*",
            "*bouncer stream halted*",
        ])
        bm.proc.wait(timeout=0.2)
        assert not bm.proc.is_running()
