# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import logging
import pytest
import requests
import time
import yaml

from lightkube.core.client import Client
from lightkube.models.rbac_v1 import PolicyRule
from lightkube.resources.core_v1 import ConfigMap
from lightkube.resources.rbac_authorization_v1 import Role
from pathlib import Path
from pytest_operator.plugin import OpsTest
from random import choices
from string import ascii_uppercase, digits

log = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())

# Charms
dex_auth = METADATA["name"]
istio_pilot = "istio-pilot"
istio_gateway = "istio-gateway"

workload_name = dex_auth + "-workload"
DEX_CONFIG = {
    "static-username": "admin",
    "static-password": "foobar",
    "service-type": "ingress",
}
secret = "".join(choices(ascii_uppercase + digits, k=30))
STATIC_CLIENT_CONFIG = yaml.dump(
    [{
        "name": "test-client",
        "id": "test-id",
        "secret": secret,
        "redirectURIs": [
            "http://localhost:8000",
            "http://localhost:18000",
        ],
    }]
)


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test: OpsTest):
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(my_charm, trust=True, config=DEX_CONFIG)
    await ops_test.model.wait_for_idle(
        apps=[dex_auth], status="active", raise_on_blocked=True, timeout=600
    )
    assert ops_test.model.applications[dex_auth].units[0].workload_status == "active"


@pytest.mark.abort_on_fail
async def test_configure_static_clients(ops_test: OpsTest):
    await ops_test.model.applications[dex_auth].set_config(
        {"static-clients": STATIC_CLIENT_CONFIG},
    )
    await ops_test.model.wait_for_idle(
        [dex_auth],
        status="active",
        wait_for_active=True,
        raise_on_blocked=True,
        raise_on_error=True,
        timeout=600,
    )
    lightkube_client = Client(namespace=ops_test.model_name)
    cm = lightkube_client.get(ConfigMap, workload_name)
    assert secret in cm.data['config.yaml']


@pytest.mark.abort_on_fail
async def test_access_page(ops_test: OpsTest):
    await ops_test.model.deploy(istio_pilot, channel="1.5/stable")
    await ops_test.model.deploy(istio_gateway, channel="1.5/stable", trust=True)
    await ops_test.model.applications[dex_auth].set_config(
        {"static-clients": STATIC_CLIENT_CONFIG},
    )
    await ops_test.model.add_relation(istio_pilot, istio_gateway)
    await ops_test.model.add_relation(
        f"{istio_pilot}:ingress",
        f"{dex_auth}:ingress",
    )
    await ops_test.model.wait_for_idle(
        [istio_gateway],
        status="waiting",
        raise_on_error=True,
        timeout=600,
    )
    lightkube_client = Client(namespace=ops_test.model_name)
    await ops_test.model.set_config({"update-status-hook-interval": "15s"})
    istio_gateway_role_name = "istio-gateway-operator"

    new_policy_rule = PolicyRule(verbs=["*"], apiGroups=["*"], resources=["*"])
    this_role = lightkube_client.get(Role, istio_gateway_role_name)
    this_role.rules.append(new_policy_rule)
    lightkube_client.patch(Role, istio_gateway_role_name, this_role)

    time.sleep(50)
    await ops_test.model.set_config({"update-status-hook-interval": "5m"})

    await ops_test.model.wait_for_idle(
        [dex_auth, istio_pilot, istio_gateway],
        status="active",
        wait_for_active=True,
        timeout=3500,
    )
    status = await ops_test.model.get_status()
    ingress_ip = status['applications'][istio_gateway]['public-address']
    public_url = f"http://{ingress_ip}.nip.io"

    await ops_test.model.applications[dex_auth].set_config(
        {"public-url": public_url},
    )

    await ops_test.model.wait_for_idle(
        [dex_auth, istio_pilot, istio_gateway],
        status="active",
        wait_for_active=True,
        raise_on_blocked=True,
        raise_on_error=True,
        timeout=600,
    )

    url = f"{public_url}/dex"
    for _ in range(60):
        try:
            requests.get(url, timeout=60)
            break
        except requests.ConnectionError:
            time.sleep(5)
    r = requests.get(url)
    assert r.status_code == 200
