import json
import urllib.error
import urllib.request
from typing import Any, cast


class HxTPAdminError(Exception):
    pass


class SyncAdminClient:
    """
    Synchronous Admin Client for controlling HxTP backend via REST API.
    """

    def __init__(self, base_url: str, api_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        data = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode("utf-8") if payload else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                resp_data = response.read().decode("utf-8")
                if not resp_data:
                    return {"status": "success"}
                return cast("dict[str, Any]", json.loads(resp_data))
        except urllib.error.HTTPError as e:
            error_text = e.read().decode("utf-8")
            raise HxTPAdminError(f"HTTP {e.code}: {error_text}") from e
        except Exception as e:
            raise HxTPAdminError(f"Request failed: {str(e)}") from e

    def get_device_state(self, device_id: str) -> dict[str, Any]:
        return self._request("GET", f"/devices/{device_id}/state")

    def get_device_capabilities(self, device_id: str) -> dict[str, Any]:
        return self._request("GET", f"/devices/{device_id}/capabilities")

    def get_device_command_history(self, device_id: str) -> dict[str, Any]:
        return self._request("GET", f"/devices/{device_id}/commands")

    def get_command_status(self, command_id: str) -> dict[str, Any]:
        return self._request("GET", f"/commands/{command_id}")

    def list_devices(self) -> dict[str, Any]:
        return self._request("GET", "/devices")

    def get_device(self, device_id: str) -> dict[str, Any]:
        return self._request("GET", f"/devices/{device_id}")

    def list_homes(self) -> dict[str, Any]:
        return self._request("GET", "/homes")

    def list_rooms(self, home_id: str) -> dict[str, Any]:
        return self._request("GET", f"/homes/{home_id}/rooms")

    def list_groups(self) -> dict[str, Any]:
        return self._request("GET", "/groups")

    # ── Provisioning & Lifecycle ────────────────────────────────────────────

    def register_device(
        self,
        device_type: str,
        home_id: str,
        room_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"device_type": device_type, "home_id": home_id}
        if room_id:
            payload["room_id"] = room_id
        return self._request("POST", "/devices/register", payload)

    def rotate_device_secret(self, device_id: str) -> dict[str, Any]:
        return self._request("POST", f"/devices/{device_id}/rotate-secret")

    def revoke_device(self, device_id: str) -> dict[str, Any]:
        return self._request("POST", f"/devices/{device_id}/revoke")

    # ── Home & Room Management ──────────────────────────────────────────────

    def create_home(self, home_name: str, timezone: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"home_name": home_name}
        if timezone:
            payload["timezone"] = timezone
        return self._request("POST", "/homes", payload)

    def update_home(
        self,
        home_id: str,
        home_name: str | None = None,
        timezone: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if home_name:
            payload["home_name"] = home_name
        if timezone:
            payload["timezone"] = timezone
        return self._request("PATCH", f"/homes/{home_id}", payload)

    def delete_home(self, home_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/homes/{home_id}")

    def create_room(self, home_id: str, name: str) -> dict[str, Any]:
        return self._request("POST", f"/homes/{home_id}/rooms", {"name": name})

    def delete_room(self, home_id: str, room_id: str) -> dict[str, Any]:
        return self._request("DELETE", f"/homes/{home_id}/rooms/{room_id}")

    # ── Group Management ────────────────────────────────────────────────────

    def create_group(
        self,
        name: str,
        slug: str,
        group_type: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": name, "slug": slug}
        if group_type:
            payload["group_type"] = group_type
        return self._request("POST", "/groups", payload)

    def add_devices_to_group(self, group_id: str, device_ids: list[str]) -> dict[str, Any]:
        return self._request("POST", f"/groups/{group_id}/devices", {"device_ids": device_ids})

    # ── Firmware ────────────────────────────────────────────────────────────

    def check_firmware_update(
        self,
        device_type: str,
        current_version: str,
        device_id: str | None = None,
    ) -> dict[str, Any]:
        qs = f"?device_type={device_type}&current_version={current_version}"
        if device_id:
            qs += f"&device_id={device_id}"
        return self._request("GET", f"/firmware/check{qs}")

    # ── Capability Manifests ────────────────────────────────────────────────

    def get_device_manifest(self, device_id: str) -> dict[str, Any]:
        return self._request("GET", f"/devices/{device_id}/manifest")

    def get_manifest_capabilities(self) -> dict[str, Any]:
        return self._request("GET", "/manifest/capabilities")

    def get_manifest_types(self) -> dict[str, Any]:
        return self._request("GET", "/manifest/types")

    # ── Command Dispatch ────────────────────────────────────────────────────

    def dispatch_command(
        self,
        target_type: str,
        target_id: str | list[str],
        action: str,
        params: dict[str, Any] | None = None,
        dry_run: bool = False,
        capability: str | None = None,
    ) -> dict[str, Any]:
        params = params or {}
        payload: dict[str, Any] = {"action": action, "params": params}

        if capability:
            payload["capability"] = capability

        if dry_run:
            if target_type != "device":
                raise ValueError("dry_run is only supported for a single 'device' target.")
            payload["dry_run"] = True

        if target_type == "device":
            t_id = target_id[0] if isinstance(target_id, list) else target_id
            return self._request("POST", f"/devices/{t_id}/command", payload)

        elif target_type == "devices":
            payload["device_ids"] = target_id if isinstance(target_id, list) else [target_id]
            return self._request("POST", "/devices/command", payload)

        elif target_type == "room":
            t_id = target_id[0] if isinstance(target_id, list) else target_id
            return self._request("POST", f"/rooms/{t_id}/command", payload)

        elif target_type == "group":
            t_id = target_id[0] if isinstance(target_id, list) else target_id
            return self._request("POST", f"/groups/{t_id}/command", payload)

        else:
            raise ValueError(f"Invalid target_type: {target_type}")

    def confirm_command(self, device_id: str, token: str) -> dict[str, Any]:
        return self._request("POST", f"/devices/{device_id}/command/confirm", {"token": token})
