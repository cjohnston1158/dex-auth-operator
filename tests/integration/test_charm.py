# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

import json
import logging
import pytest
import requests
import yaml

from lightkube.core.client import Client
from lightkube.resources.core_v1 import ConfigMap
from pathlib import Path
from pytest_operator.plugin import OpsTest
from random import choices
from string import ascii_uppercase, digits
from tenacity import (
    Retrying,
    stop_after_attempt,
    stop_after_delay,
    wait_exponential,
)

log = logging.getLogger(__name__)
METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())

# Charms
dex_auth = METADATA["name"]
oidc_gatekeeper = "oidc-gatekeeper"
istio_pilot = "istio-pilot"
istio_gateway = "istio-gateway"
prometheus = "prometheus-k8s"
grafana = "grafana-k8s"

workload_name = dex_auth + "-workload"

# Configs
DEX_CONFIG = {
    "static-username": "admin",
    "static-password": "foobar",
}
secret = "".join(choices(ascii_uppercase + digits, k=30))
client_name = "test client"
OIDC_CONFIG = {
    "client-name": client_name,
    "client-secret": secret,
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
async def test_build_and_deploy(ops_test):
    my_charm = await ops_test.build_charm(".")
    await ops_test.model.deploy(my_charm, trust=True, config=DEX_CONFIG)
    await ops_test.model.wait_for_idle(
        apps=[dex_auth], status="active", raise_on_blocked=True, timeout=600
    )
    assert ops_test.model.applications[dex_auth].units[0].workload_status == "active"


@pytest.mark.abort_on_fail
async def test_relations(ops_test: OpsTest):
    public_url = "http://1.2.3.4"
    await ops_test.model.deploy(oidc_gatekeeper, channel="latest/edge", config=OIDC_CONFIG)
    await ops_test.model.deploy(istio_pilot, channel="1.5/stable")
    await ops_test.model.add_relation(oidc_gatekeeper, dex_auth)
    await ops_test.model.add_relation(f"{istio_pilot}:ingress", f"{dex_auth}:ingress")

    await ops_test.model.applications[dex_auth].set_config({"public-url": public_url})
    await ops_test.model.applications[oidc_gatekeeper].set_config({"public-url": public_url})

    await ops_test.model.wait_for_idle(
        [dex_auth, oidc_gatekeeper, istio_pilot],
        status="active",
        wait_for_active=True,
        raise_on_blocked=True,
        raise_on_error=True,
        timeout=600,
    )

    """
    We should check that the oidc-gatekeeper client-secret is correct in the
    dex cm, however a bug in the oidc-gatekeeper charm currently prevents this
    from properly working:
        https://github.com/canonical/oidc-gatekeeper-operator/issues/27
    """
    lightkube_client = Client(namespace=ops_test.model_name)
    cm = lightkube_client.get(ConfigMap, workload_name)
    # assert secret in cm.data['config.yaml']
    assert public_url in cm.data['config.yaml']
    assert client_name in cm.data['config.yaml']


async def test_prometheus_grafana_integration(ops_test: OpsTest):
    """Deploy prometheus, grafana and required relations, then test the metrics."""
    prometheus_scrape_charm = "prometheus-scrape-config-k8s"
    scrape_config = {"scrape_interval": "5s"}

    await ops_test.model.deploy(prometheus, channel="latest/beta", trust=True)
    await ops_test.model.deploy(grafana, channel="latest/beta", trust=True)
    await ops_test.model.add_relation(prometheus, grafana)
    await ops_test.model.add_relation(dex_auth, grafana)
    await ops_test.model.deploy(
        prometheus_scrape_charm, channel="latest/beta", config=scrape_config
    )
    await ops_test.model.add_relation(dex_auth, prometheus_scrape_charm)
    await ops_test.model.add_relation(prometheus, prometheus_scrape_charm)

    await ops_test.model.wait_for_idle(status="active", timeout=60 * 10)

    status = await ops_test.model.get_status()
    prometheus_unit_ip = status["applications"][prometheus]["units"][f"{prometheus}/0"][
        "address"
    ]
    log.info(f"Prometheus available at http://{prometheus_unit_ip}:9090")

    for attempt in retry_for_5_attempts:
        log.info(
            f"Testing prometheus deployment (attempt "
            f"{attempt.retry_state.attempt_number})"
        )
        with attempt:
            r = requests.get(
                f'http://{prometheus_unit_ip}:9090/api/v1/query?'
                f'query=up{{juju_application="{dex_auth}"}}'
            )
            response = json.loads(r.content.decode("utf-8"))
            response_status = response["status"]
            log.info(f"Response status is {response_status}")
            assert response_status == "success"

            response_metric = response["data"]["result"][0]["metric"]
            assert response_metric["juju_application"] == dex_auth
            assert response_metric["juju_model"] == ops_test.model_name


# Helper to retry calling a function over 30 seconds or 5 attempts
retry_for_5_attempts = Retrying(
    stop=(stop_after_attempt(5) | stop_after_delay(30)),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    reraise=True,
)
