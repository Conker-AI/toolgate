"""Private replacement payload preparation. Does not dispatch Docker effects."""

import copy
import hashlib
import json
import re
from dataclasses import dataclass, field

from toolgate.executors.port_plan import PlanError
from toolgate.executors.port_preview import from_inspection

# ContainerConfig create fields from the Docker Engine v1.45 OpenAPI schema.
CONFIG_FIELDS = {
    "Hostname", "Domainname", "User", "AttachStdin", "AttachStdout", "AttachStderr",
    "ExposedPorts", "Tty", "OpenStdin", "StdinOnce", "Env", "Cmd", "Healthcheck",
    "ArgsEscaped", "Image", "Volumes", "WorkingDir", "Entrypoint", "NetworkDisabled",
    "MacAddress", "OnBuild", "Labels", "StopSignal", "StopTimeout", "Shell",
}
NETWORK_FIELDS = ("IPAMConfig", "Links", "MacAddress", "Aliases", "DriverOpts")


@dataclass(repr=False)
class Replacement:
    """Internal only: payload contains credentials. Never serialize to a receipt."""

    preview: dict
    _body: dict = field(repr=False)
    _source: str = field(repr=False)
    name: str

    def __repr__(self):
        return "<Private container replacement specification>"

    def create_body(self, snapshot_image):
        # The eventual executor must commit the stopped source writable layer and
        # journal its image ID. Reusing the original image would discard changes.
        if not isinstance(snapshot_image, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", snapshot_image):
            raise PlanError("invalid")
        result = copy.deepcopy(self._body)
        result["Image"] = snapshot_image
        return result

    def matches(self, inspection):
        """Private stale-configuration check, excluding volatile runtime state."""
        try:
            return self._source == _fingerprint(inspection)
        except (KeyError, TypeError, ValueError, RecursionError, AttributeError):
            return False


def _fingerprint(inspection):
    # This digest stays inside the private object, never an approval token.
    value = {key: inspection[key] for key in ("Id", "Name", "Image", "Config", "HostConfig", "Mounts")}
    value["networks"] = {
        name: {key: endpoint.get(key) for key in (*NETWORK_FIELDS, "NetworkID")}
        for name, endpoint in inspection["NetworkSettings"]["Networks"].items()
    }
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def _preserve_volumes(host, mounts):
    if not isinstance(mounts, list) or len(mounts) > 200:
        raise PlanError("invalid")
    if host.get("VolumesFrom") or host.get("ContainerIDFile"):
        raise PlanError("unsupported")
    declarations = host.get("Mounts") or []
    binds = host.get("Binds") or []
    if not isinstance(declarations, list) or not isinstance(binds, list):
        raise PlanError("invalid")
    declarations = copy.deepcopy(declarations)
    by_target = {}
    for item in declarations:
        if not isinstance(item, dict) or not isinstance(item.get("Target"), str):
            raise PlanError("invalid")
        if item["Target"] in by_target:
            raise PlanError("invalid")
        by_target[item["Target"]] = item
    bound = {}
    for item in binds:
        if not isinstance(item, str):
            raise PlanError("invalid")
        parts = item.split(":")
        if len(parts) not in (2, 3) or not parts[1].startswith("/"):
            raise PlanError("unsupported")
        if parts[1] in bound or parts[1] in by_target:
            raise PlanError("invalid")
        bound[parts[1]] = parts[0]
    seen = set()
    for mount in mounts:
        if not isinstance(mount, dict):
            raise PlanError("invalid")
        target = mount.get("Destination")
        if not isinstance(target, str) or not target.startswith("/") or target in seen:
            raise PlanError("invalid")
        seen.add(target)
        kind = mount.get("Type")
        if kind == "volume":
            name = mount.get("Name")
            if not isinstance(name, str) or not name or type(mount.get("RW")) is not bool:
                raise PlanError("invalid")
            if target in bound:
                if bound[target] != name:
                    raise PlanError("invalid")
                continue
            if target in by_target:
                declaration = by_target[target]
                if declaration.get("Type") != "volume":
                    raise PlanError("invalid")
                if declaration.get("Source") not in (None, "", name):
                    raise PlanError("invalid")
                # Resolve anonymous Mounts declarations without losing options.
                declaration["Source"] = name
            else:
                declarations.append({"Type": "volume", "Source": name, "Target": target,
                                     "ReadOnly": not mount["RW"],
                                     "VolumeOptions": {"NoCopy": True}})
        elif kind == "bind":
            if target not in bound and target not in by_target:
                raise PlanError("unsupported")
        elif kind == "tmpfs":
            if target not in (host.get("Tmpfs") or {}) and target not in by_target:
                raise PlanError("unsupported")
        else:
            raise PlanError("unsupported")
    host["Mounts"] = declarations


def prepare(container_id, inspection, operation, *, mapping=None, original=None):
    """Prepare from a private inspect response; no returned public raw config."""
    preview = from_inspection(container_id, inspection, operation, mapping=mapping, original=original)
    try:
        config, host = copy.deepcopy(inspection["Config"]), copy.deepcopy(inspection["HostConfig"])
        if not isinstance(config, dict) or set(config) - CONFIG_FIELDS:
            raise PlanError("unsupported")
        name = inspection["Name"]
        if not isinstance(name, str) or not re.fullmatch(r"/[a-zA-Z0-9][a-zA-Z0-9_.-]*", name):
            raise PlanError("invalid")
        # External container namespaces cannot be faithfully moved by recreating
        # only this container. A separate owner-reviewed migration is required.
        if any(str(host.get(key, "")).startswith("container:") for key in ("PidMode", "IpcMode")):
            raise PlanError("unsupported")
        _preserve_volumes(host, inspection["Mounts"])
        ports = {}
        exposed = config.get("ExposedPorts") or {}
        if not isinstance(exposed, dict):
            raise PlanError("invalid")
        for binding in preview["after"]:
            key = f'{binding["containerPort"]}/{binding["protocol"]}'
            ports.setdefault(key, []).append({"HostIp": binding["hostAddress"],
                                              "HostPort": str(binding["hostPort"])})
            exposed.setdefault(key, {})
        host["PortBindings"] = ports
        config["ExposedPorts"] = exposed
        endpoints = {}
        networks = inspection["NetworkSettings"]["Networks"]
        if not isinstance(networks, dict) or len(networks) > 64:
            raise PlanError("invalid")
        for network, endpoint in networks.items():
            if not isinstance(endpoint, dict) or not isinstance(network, str) or not network:
                raise PlanError("invalid")
            endpoints[network] = {key: copy.deepcopy(endpoint[key]) for key in NETWORK_FIELDS if key in endpoint}
        config["HostConfig"] = host
        config["NetworkingConfig"] = {"EndpointsConfig": endpoints}
        preview["writableLayer"] = "snapshot_required"
        preview["volumeData"] = "reuse_existing"
        preview["tmpfsData"] = "reset_on_replacement" if any(
            mount["Type"] == "tmpfs" for mount in inspection["Mounts"]
        ) else "none"
        return Replacement(preview, config, _fingerprint(inspection), name[1:])
    except PlanError:
        raise
    except (KeyError, TypeError, ValueError, RecursionError):
        raise PlanError("invalid") from None
