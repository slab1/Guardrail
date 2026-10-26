import os
import pytest
@pytest.fixture(scope='session', autouse=True)
def clear_nonce_db():
    db = os.path.abspath(os.path.join(os.path.dirname(__file__), '../data/consumed_nonces.db'))
    try:
        os.remove(db)
    except FileNotFoundError:
        pass
