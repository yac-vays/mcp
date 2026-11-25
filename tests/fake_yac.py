"""
A fake YAC backend for respx: serves the schemas captured from a real YAC
(fixtures/schemas.json, generated from fixtures/yac-specs.yml) and mimics the
endpoints the gateway uses closely enough for the flows (validate with
NewEntity / ReplaceEntity / UpdateEntity, canonical YAML, commits).
"""

import copy
import json
import re
from pathlib import Path

import httpx
import jsonschema
import respx

from app.lib import yaml as yamllib

FIXTURES = Path(__file__).parent / "fixtures"
SCHEMAS = json.loads((FIXTURES / "schemas.json").read_text())
TYPES = json.loads((FIXTURES / "types.json").read_text())
URL = "https://yac-hosts.test"
PERMS = ["act", "add", "adm", "cln", "del", "edt", "see"]


def _merge(base, patch):
    """YAC's UpdateEntity semantics, in place on a round-trip document."""
    if isinstance(base, dict) and isinstance(patch, dict):
        for key, value in patch.items():
            if value == "~undefined":
                base.pop(key, None)
            elif isinstance(base.get(key), dict) and isinstance(value, dict):
                _merge(base[key], value)
            else:
                base[key] = value
        return base
    return patch


class FakeYac:
    def __init__(self, files: dict[str, str] | None = None):
        self.files = dict(files or {})
        self.requests: list[httpx.Request] = []
        self.commits: list[dict] = []
        self.schemas = copy.deepcopy(SCHEMAS)
        self.log_content = "---\nos: linux\n"
        # Set to report a failed after-action of the next write (YAC-Warning)
        self.after_action_warning = ""
        # Limit usages, measured (like YAC) only for the operations a limit is on
        self.usages: list[dict] = []
        self.perms = list(PERMS)

    def _validated(self, data: dict, text: str) -> dict:
        errors = sorted(
            jsonschema.Draft7Validator(self.schemas["json_schema"]).iter_errors(data),
            key=lambda e: list(e.absolute_path),
        )
        schemas = {**copy.deepcopy(self.schemas), "data": data, "yaml": text, "valid": not errors}
        if errors:
            schemas["message"] = errors[0].message
            schemas["data_loc"] = "#/" + "/".join(str(p) for p in errors[0].absolute_path)
        return {"schemas": schemas, "request": {"valid": True}, "usages": [], "perms": self.perms}

    def validate(self, body: dict) -> dict:
        entity = body.get("entity") or {}
        if body["operation"] == "read":
            text = self.files[body["name"]]
        elif "yaml" in entity:
            text = entity["yaml"]
        elif "yaml_new" in entity:
            text = entity["yaml_new"]
        else:
            base = entity.get("yaml_base") or self.files[body["name"]]
            text = yamllib.dump(_merge(yamllib.load(base), entity["data"]))
        data = yamllib.plain(yamllib.load(text))
        result = self._validated(data, yamllib.dump(yamllib.load(text)))
        if body["operation"] in ("create", "edit"):
            result["usages"] = copy.deepcopy(self.usages)
        if body["operation"] == "create" and not entity.get("name"):  # name_generated: never
            result["request"] = {
                "valid": False, "message": "The entity.name must be set for this operation"
            }
        return result

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path, method = request.url.path, request.method
        if path == "/entity" and method == "GET":
            return httpx.Response(200, json=TYPES)
        if path == "/validate":
            return httpx.Response(200, json=self.validate(json.loads(request.content)))
        if m := re.fullmatch(r"/entity/host/([^/]+)/yaml", path):
            if m[1] not in self.files:
                return httpx.Response(404, json={"title": "Not Found", "message": "no such entity"})
            return httpx.Response(200, text=self.files[m[1]])
        if m := re.fullmatch(r"/entity/host/([^/]+)/logs", path):
            entry = {"name": "facts", "message": "gathered", "time": "2026-11-25",
                     "progress": None, "problem": None, "has_content": True}
            return httpx.Response(200, json=[entry])
        if m := re.fullmatch(r"/entity/host/([^/]+)/logs/([^/]+)/content", path):
            if m[2] != "facts":
                return httpx.Response(404, json={"title": "Not Found", "message": "no such log"})
            body = {"name": "facts", "time": "2026-11-25", "content": self.log_content}
            return httpx.Response(200, json=body)
        if path == "/entity/host" and method == "GET":
            return httpx.Response(
                200, json={"hash": "h", "list": [{"name": n, "perms": PERMS} for n in self.files]}
            )
        if path == "/entity/host" and method == "POST":
            body = json.loads(request.content)
            self.files[body["name"]] = body["yaml"]
            self.commits.append({"method": "create", "msg": request.url.params["msg"], **body})
            return httpx.Response(201, json={"name": body["name"], "hash": "h", "patch": "+..."})
        if m := re.fullmatch(r"/entity/host/([^/]+)", path):
            if method == "PUT":
                body = json.loads(request.content)
                if self.files.get(m[1]) != body["yaml_old"]:
                    return httpx.Response(409, json={"title": "Conflict", "message": "changed"})
                if body["yaml_new"] == body["yaml_old"]:
                    return httpx.Response(
                        400,
                        json={"title": "Invalid Request",
                              "message": "The request does not change anything"},
                    )
                self.files[m[1]] = body["yaml_new"]
                self.commits.append({"method": "edit", "msg": request.url.params["msg"], **body})
                headers = {}
                if self.after_action_warning:
                    headers["YAC-Warning"] = self.after_action_warning
                return httpx.Response(
                    200, json={"name": m[1], "hash": "h", "patch": "~..."}, headers=headers
                )
            if method == "DELETE":
                self.files.pop(m[1])
                return httpx.Response(204)
        return httpx.Response(404, json={"title": "Not Found", "message": path})

    def mock(self, router: respx.MockRouter) -> "FakeYac":
        router.route(host="yac-hosts.test").mock(side_effect=self.handle)
        router.route(host="yac-down.test").mock(side_effect=httpx.ConnectError("refused"))
        return self
