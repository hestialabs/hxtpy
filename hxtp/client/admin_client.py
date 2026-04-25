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

        data = json.dumps(payload).encode("utf-8") if payload else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                resp_data = response.read().decode("utf-8")
                if not resp_data:
                    return {"status": "success"}
                return cast(dict[str, Any], json.loads(resp_data))
        except urllib.error.HTTPError as e:
            error_text = e.read().decode("utf-8")
            raise HxTPAdminError(f"HTTP {e.code}: {error_text}") from e
        except Exception as e:
            raise HxTPAdminError(f"Request failed: {str(e)}") from e

    def get_device_state(self, device_id: str) -> dict[str, Any]:
        return self._request("GET", f"/device/{device_id}/state")

    def get_device_capabilities(self, device_id: str) -> dict[str, Any]:
        return self._request("GET", f"/devices/{device_id}/capabilities")

    def get_device_command_history(self, device_id: str) -> dict[str, Any]:
        return self._request("GET", f"/device/{device_id}/commands")

    def get_command_status(self, command_id: str) -> dict[str, Any]:
        return self._request("GET", f"/commands/{command_id}")

    def dispatch_command(
        self,
        target_type: str,
        target_id: str | list[str],
        action: str,
        params: dict[str, Any] | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        params = params or {}
        payload: dict[str, Any] = {"action": action, "params": params}

        if dry_run:
            if target_type != "device":
                raise ValueError("dry_run is only supported for a single 'device' target.")
            payload["dry_run"] = True

        if target_type == "device":
            t_id = target_id[0] if isinstance(target_id, list) else target_id
            return self._request("POST", f"/device/{t_id}/command", payload)

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
        return self._request("POST", f"/device/{device_id}/command/confirm", {"token": token})
