#!/usr/bin/env python3

import logging
import random
import string
import subprocess
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import yaml

from ops.charm import CharmBase
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus, WaitingStatus, BlockedStatus
from ops.framework import StoredState

from kubernetes_wrapper import Kubernetes
from serialized_data_interface import (
    NoCompatibleVersions,
    NoVersionsListed,
    get_interfaces,
)

try:
    import bcrypt
except ImportError:
    subprocess.check_call(["apt", "update"])
    subprocess.check_call(["apt", "install", "-y", "python3-bcrypt"])
    import bcrypt


class Operator(CharmBase):
    _stored = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        if not self.unit.is_leader():
            # We can't do anything useful when not the leader, so do nothing.
            self.model.unit.status = WaitingStatus("Waiting for leadership")
            return
        self.log = logging.getLogger(__name__)

        try:
            self.interfaces = get_interfaces(self)
        except NoVersionsListed as err:
            self.model.unit.status = WaitingStatus(str(err))
            return
        except NoCompatibleVersions as err:
            self.model.unit.status = BlockedStatus(str(err))
            return
        else:
            self.model.unit.status = ActiveStatus()

        self._stored.set_default(username="admin")
        self._stored.set_default(
            password="".join(random.choices(string.ascii_letters, k=30))
        )
        generated_salt = bcrypt.gensalt()
        self._stored.set_default(salt=generated_salt)
        self._stored.set_default(user_id=str(uuid4()))
        self.kubernetes = Kubernetes(self.model.name)

        self.framework.observe(self.on.dex_auth_pebble_ready, self.pebble_main)
        self.framework.observe(self.on.config_changed, self.pebble_main)
        self.framework.observe(self.on.oidc_client_relation_changed, self.pebble_main)
        self.framework.observe(self.on["ingress"].relation_changed, self.send_info)
        self.framework.observe(self.on.stop, self._on_stop)

    def send_info(self, event):
        if self.interfaces["ingress"]:
            self.interfaces["ingress"].send_data(
                {
                    "prefix": "/dex",
                    "rewrite": "/dex",
                    "service": self.model.app.name,
                    "port": self.model.config["port"],
                }
            )

    def pebble_main(self, event):
        connectors = yaml.safe_load(self.model.config["connectors"])
        port = self.model.config["port"]
        public_url = self.model.config["public-url"]

        if (oidc_client := self.interfaces["oidc-client"]) and oidc_client.get_data():
            oidc_client_info = list(oidc_client.get_data().values())
        else:
            oidc_client_info = []

        # Allows setting a basic username/password combo
        static_username = self.model.config["static-username"]
        static_password = self.model.config["static-password"]

        static_config = {}
        self.kubernetes.apply(Path("resources/crds.yaml").read_text())

        # Dex needs some way of logging in, so if nothing has been configured,
        # just generate a username/password
        if not static_username:
            static_username = self._stored.username

        if not static_password:
            static_password = self._stored.password

        salt = self._stored.salt
        user_id = self._stored.user_id

        hashed = bcrypt.hashpw(static_password.encode("utf-8"), salt).decode("utf-8")
        static_config = {
            "enablePasswordDB": True,
            "staticPasswords": [
                {
                    "email": static_username,
                    "hash": hashed,
                    "username": static_username,
                    "userID": user_id,
                }
            ],
        }

        config = yaml.dump(
            {
                "issuer": f"{public_url}/dex",
                "storage": {"type": "kubernetes", "config": {"inCluster": True}},
                "web": {"http": f"0.0.0.0:{port}"},
                "logger": {"level": "debug", "format": "text"},
                "oauth2": {"skipApprovalScreen": True},
                "staticClients": oidc_client_info,
                "connectors": connectors,
                **static_config,
            }
        )

        container = self.unit.get_container("dex-auth")

        pebble_layer = {
            "summary": "dex layer",
            "description": "pebble config layer for dex-auth",
            "services": {
                "dex-auth": {
                    "override": "replace",
                    "summary": "dex",
                    "command": "dex serve /etc/dex/cfg/config.yaml",
                    "startup": "enabled",
                    "environment": {"KUBERNETES_POD_NAMESPACE": self.model.name},
                }
            },
        }
        container.make_dir("/etc/dex/cfg", make_parents=True)
        container.push("/etc/dex/cfg/config.yaml", config)
        container.add_layer("dex-auth", pebble_layer, combine=True)
        if container.get_service("dex-auth").is_running():
            container.stop("dex-auth")
        container.start("dex-auth")
        self.unit.status = ActiveStatus()

    def _on_stop(self, event):
        self.kubernetes.delete(Path("resources/crds.yaml").read_text())


if __name__ == "__main__":
    main(Operator)
