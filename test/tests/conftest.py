import contextlib

import pytest

# from pytest_cs import plugin

# pytest_exception_interact = plugin.pytest_exception_interact


# provide the name of the bouncer binary to test
@pytest.fixture(scope='session')
def bouncer_under_test():
    return 'crowdsec-blocklist-mirror'


# Create a lapi container, register a bouncer and run it with the updated config.
# - Return context manager that yields a tuple of (bouncer, lapi)
@pytest.fixture(scope='session')
def bouncer_with_lapi(bouncer, crowdsec, bm_cfg_factory, api_key_factory, tmp_path_factory, bouncer_binary):
    @contextlib.contextmanager
    def closure(config_lapi=None, config_bouncer=None, api_key=None):
        if config_bouncer is None:
            config_bouncer = {}
        if config_lapi is None:
            config_lapi = {}
        # can be overridden by config_lapi + config_bouncer
        api_key = api_key_factory()
        env = {
            'BOUNCER_KEY_custom': api_key,
        }
        try:
            env.update(config_lapi)
            with crowdsec(environment=env) as lapi:
                lapi.wait_for_http(8080, '/health')
                port = lapi.probe.get_bound_port('8080')
                cfg = bm_cfg_factory()
                cfg.setdefault('crowdsec_config', {})
                cfg['crowdsec_config']['lapi_url'] = f'http://localhost:{port}/'
                cfg['crowdsec_config']['lapi_key'] = api_key
                cfg.update(config_bouncer)
                with bouncer(cfg) as cb:
                    yield cb, lapi
        finally:
            pass

    yield closure


_default_config = {
    'update_frequency': '0.1s',
    'log_mode': 'stdout',
    'log_level': 'info',
    'prometheus': {
        'enabled': False,
    }
}


@pytest.fixture(scope='session')
def bm_cfg_factory():
    def closure(**kw):
        cfg = _default_config.copy()
        cfg.setdefault('crowdsec_config', {})
        cfg |= kw
        return cfg | kw
    yield closure
