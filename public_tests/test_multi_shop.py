import asyncio
import json

import pytest

from shopee_mcp.credentials import CredentialError
from shopee_mcp.multi_shop import (SHOP_ARGUMENT, SHOP_ARGUMENT_SCHEMA, MultiShopError, MultiShopRegistry,
                                   load_shop_config)
from test_credentials import make_env


class FakeTransport:
    instances = []

    def __init__(self, store, **kwargs):
        self.store, self.kwargs, self.closed = store, kwargs, False
        self.secrets = {f"secret-{store.path.name}"}
        FakeTransport.instances.append(self)

    async def close(self):
        self.closed = True


class FailingCloseTransport(FakeTransport):
    async def close(self):
        self.closed = True
        raise RuntimeError("/secret/path boom")


@pytest.fixture(autouse=True)
def reset_instances():
    FakeTransport.instances = []


@pytest.fixture
def base(tmp_path):
    tmp_path.chmod(0o700)
    return tmp_path


def env(base, name, shop_id, **overrides):
    path = base / f"{name}.env"
    values = dict(SHOPEE_SHOP_ID=str(shop_id), SHOPEE_ACCESS_TOKEN=f"access-{name}",
                  SHOPEE_REFRESH_TOKEN=f"refresh-{name}")
    values.update(overrides)
    make_env(path, **values)
    return path


def config(base, shops, mode=0o600, name="shops.json"):
    path = base / name
    path.write_text(json.dumps({"shops": {alias: str(value) for alias, value in shops.items()}}))
    path.chmod(mode)
    return path


def registry(base, **kwargs):
    shops = {"store-a": env(base, "a", 111), "store-b": env(base, "b", 222)}
    return MultiShopRegistry(shops, transport_factory=FakeTransport, timeout=5.0, **kwargs)


def assert_safe(error, base):
    text = str(error)
    assert str(base) not in text and ".env" not in text and "secret" not in text and "access-" not in text


def test_each_alias_gets_its_own_store_and_cached_transport(base):
    reg = registry(base)
    assert reg.aliases == ("store-a", "store-b")
    a, b = reg.transport("store-a"), reg.transport("store-b")
    assert a is reg.transport("store-a") and a is not b
    assert a.store is reg.store("store-a") and b.store is reg.store("store-b")
    assert a.store.snapshot().subject_id == 111 and b.store.snapshot().subject_id == 222
    assert a.kwargs == {"timeout": 5.0}
    assert reg.secrets == {"secret-a.env", "secret-b.env"}


def test_construction_is_lazy_and_does_not_write_files(base):
    reg = registry(base)
    before = sorted(p.name for p in base.iterdir())
    assert FakeTransport.instances == []
    reg.describe()
    assert sorted(p.name for p in base.iterdir()) == before


@pytest.mark.parametrize("alias", [None, "", "STORE-A", "store-a ", "store", "store-a/..", 1, "store-c"])
def test_alias_is_explicit_and_exact_without_fallback(base, alias):
    reg = registry(base)
    with pytest.raises(MultiShopError) as caught:
        reg.transport(alias)
    assert str(caught.value) in {"shop_alias_required", "invalid_shop_alias", "unknown_shop_alias"}
    assert FakeTransport.instances == []


def test_split_arguments_pops_shop_without_mutating_input(base):
    reg = registry(base)
    original = {SHOP_ARGUMENT: "store-b", "offset": 0}
    assert reg.split_arguments(original) == ("store-b", {"offset": 0})
    assert original == {SHOP_ARGUMENT: "store-b", "offset": 0}
    with pytest.raises(MultiShopError, match="shop_alias_required"):
        reg.split_arguments({"offset": 0})
    with pytest.raises(MultiShopError, match="shop_alias_required"):
        reg.split_arguments(None)
    with pytest.raises(MultiShopError, match="unknown_shop_alias"):
        reg.split_arguments({SHOP_ARGUMENT: "store-z"})


def test_schema_pattern_matches_alias_rules():
    assert SHOP_ARGUMENT_SCHEMA["type"] == "string" and SHOP_ARGUMENT_SCHEMA["pattern"].startswith("^")


def test_legacy_single_shop_allows_omitted_alias_only(base):
    reg = MultiShopRegistry.from_single(env(base, "only", 333), transport_factory=FakeTransport)
    assert reg.aliases == ("default",)
    assert reg.split_arguments({"offset": 1}) == ("default", {"offset": 1})
    assert reg.transport(None) is reg.transport("default")
    with pytest.raises(MultiShopError, match="unknown_shop_alias"):
        reg.transport("other")
    with pytest.raises(MultiShopError):
        MultiShopRegistry({"a": env(base, "x", 1), "b": env(base, "y", 2)}, implicit_single=True,
                          transport_factory=FakeTransport)


def test_describe_exposes_no_paths_ids_or_secrets(base):
    text = json.dumps(registry(base).describe())
    assert json.loads(text) == [{"alias": "store-a", "env": "sandbox"}, {"alias": "store-b", "env": "sandbox"}]
    for leaked in (str(base), ".env", "111", "123456", "partner-secret", "access-a", "refresh-b"):
        assert leaked not in text
    assert "a.env" not in repr(registry(base))


def test_config_file_round_trip(base):
    path = config(base, {"store-a": env(base, "a", 111), "store-b": env(base, "b", 222)})
    reg = MultiShopRegistry.from_config_file(path, transport_factory=FakeTransport)
    assert reg.aliases == ("store-a", "store-b")
    assert not reg.implicit_single
    with pytest.raises(MultiShopError, match="shop_alias_required"):
        reg.transport(None)
    with pytest.raises(MultiShopError):
        MultiShopRegistry.from_config_file(path, implicit_single=True, transport_factory=FakeTransport)


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o400, 0o700])
def test_config_file_requires_0600(base, mode):
    path = config(base, {"store-a": env(base, "a", 111)}, mode=mode)
    with pytest.raises(MultiShopError) as caught:
        load_shop_config(path)
    assert_safe(caught.value, base)


def test_config_path_must_be_absolute_normalized_and_not_symlink(base):
    path = config(base, {"store-a": env(base, "a", 111)})
    (base / "sub").mkdir()
    for bad in ("shops.json", f"{base}/./shops.json", f"{base}/sub/../shops.json", f"{base}//shops.json"):
        with pytest.raises(MultiShopError) as caught:
            load_shop_config(bad)
        assert_safe(caught.value, base)
    link = base / "link.json"
    link.symlink_to(path)
    with pytest.raises(MultiShopError, match="symlink"):
        load_shop_config(link)
    with pytest.raises(MultiShopError):
        load_shop_config(base / "missing.json")


def test_config_directory_must_not_be_shared_writable(base):
    shared = base / "shared"
    shared.mkdir()
    path = config(shared, {"store-a": env(base, "a", 111)})
    shared.chmod(0o777)
    try:
        with pytest.raises(MultiShopError, match="writable"):
            load_shop_config(path)
    finally:
        shared.chmod(0o700)


@pytest.mark.parametrize("content", [
    "not json", "[]", '{"shops": []}', '{"shops": {}, "extra": 1}', '{"shops": {"Bad": "/x"}}',
    '{"shops": {"a": 5}}', '{"shops": {"a": "relative.env"}}', '{"shops": {"a": "/x", "a": "/y"}}',
])
def test_config_content_is_strict(base, content):
    path = base / "shops.json"
    path.write_text(content)
    path.chmod(0o600)
    with pytest.raises(MultiShopError) as caught:
        MultiShopRegistry.from_config_file(path, transport_factory=FakeTransport)
    assert_safe(caught.value, base)


def test_empty_config_is_rejected(base):
    with pytest.raises(MultiShopError):
        MultiShopRegistry.from_config_file(config(base, {}), transport_factory=FakeTransport)


def test_env_file_paths_are_audited(base):
    good = env(base, "a", 111)
    link = base / "link.env"
    link.symlink_to(good)
    loose = env(base, "loose", 444)
    loose.chmod(0o644)
    for bad in ({"store-a": link}, {"store-a": loose}, {"store-a": "a.env"},
                {"store-a": f"{base}/../{base.name}/a.env"}, {"store-a": f"{base}/./a.env"},
                {"store-a": base / "missing.env"}):
        with pytest.raises(MultiShopError) as caught:
            MultiShopRegistry(bad, transport_factory=FakeTransport)
        assert_safe(caught.value, base)
    with pytest.raises(MultiShopError):
        load_shop_config(config(base, {"store-a": link}))
    config_path = base / "self.json"
    config_path.write_text(json.dumps({"shops": {"store-a": str(config_path)}}))
    config_path.chmod(0o600)
    with pytest.raises(MultiShopError):
        load_shop_config(config_path)


def test_aliases_must_not_share_file_or_shop_identity(base):
    a = env(base, "a", 111)
    with pytest.raises(MultiShopError, match="distinct env files"):
        MultiShopRegistry({"store-a": a, "store-b": a}, transport_factory=FakeTransport)
    same_shop = env(base, "dup", 111)
    with pytest.raises(MultiShopError, match="distinct shops"):
        MultiShopRegistry({"store-a": a, "store-b": same_shop}, transport_factory=FakeTransport)


def test_invalid_credentials_fail_closed_without_leaking(base):
    broken = env(base, "broken", 555, SHOPEE_SHOP_ID="")
    with pytest.raises(MultiShopError) as caught:
        MultiShopRegistry({"store-a": env(base, "a", 111), "store-b": broken}, transport_factory=FakeTransport)
    assert isinstance(caught.value, CredentialError)
    assert_safe(caught.value, base)


def test_close_is_idempotent_and_blocks_further_use(base):
    reg = registry(base)
    a, b = reg.transport("store-a"), reg.transport("store-b")
    asyncio.run(reg.close())
    asyncio.run(reg.close())
    assert a.closed and b.closed and reg.closed
    for call in (lambda: reg.transport("store-a"), lambda: reg.split_arguments({SHOP_ARGUMENT: "store-a"}),
                 reg.describe):
        with pytest.raises(MultiShopError, match="shop_registry_closed"):
            call()


def test_close_closes_all_even_when_one_fails(base):
    shops = {"store-a": env(base, "a", 111), "store-b": env(base, "b", 222)}
    reg = MultiShopRegistry(shops, transport_factory=FailingCloseTransport)
    first, second = reg.transport("store-a"), reg.transport("store-b")
    with pytest.raises(MultiShopError) as caught:
        asyncio.run(reg.close())
    assert first.closed and second.closed
    assert str(caught.value) == "shop_registry_close_failed"


def test_async_context_manager_closes(base):
    async def scenario():
        async with registry(base) as reg:
            transport = reg.transport("store-b")
        return reg, transport
    reg, transport = asyncio.run(scenario())
    assert transport.closed and reg.closed


def test_default_transport_factory_constructs_without_network(base):
    pytest.importorskip("httpx")
    from shopee_mcp.transport import Transport
    reg = MultiShopRegistry({"store-a": env(base, "a", 111)}, timeout=3.0, concurrency=2)
    transport = reg.transport("store-a")
    assert isinstance(transport, Transport) and transport.store is reg.store("store-a")
    asyncio.run(reg.close())
