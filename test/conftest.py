"""
Full integration test with a real Crowdsec running in Docker
"""

import contextlib
import os
import pathlib
import secrets
import string

import pytest

SCRIPT_DIR = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent
bm_binary = PROJECT_ROOT.joinpath("crowdsec-blocklist-mirror")


# Create a lapi container, registers a bouncer
# and runs it with the updated config.
# - Returns context manager that yields a tuple of (bouncer, lapi)
@pytest.fixture(scope='session')
def bouncer_with_lapi(bouncer, crowdsec, bm_cfg_factory, api_key_factory, tmp_path_factory):
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
                with bouncer(bm_binary, cfg) as cb:
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


@pytest.fixture(scope='session')
def api_key_factory():
    def closure(alphabet=string.ascii_letters + string.digits):
        return ''.join(secrets.choice(alphabet) for i in range(32))
    yield closure
