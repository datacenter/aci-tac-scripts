"""APIC HTTP client with cookie-based authentication."""

from __future__ import annotations

import os
import re

import httpx


class ApicClient:
    """Async client for Cisco APIC REST API and documentation endpoints."""

    def __init__(self) -> None:
        self.base_url = os.environ["APIC_URL"].rstrip("/")
        self._user = os.environ["APIC_USER"]
        self._password = os.environ["APIC_PASS"]
        self._token: str | None = None
        self._client = httpx.AsyncClient(verify=False, timeout=30.0)

    async def login(self) -> None:
        """Authenticate to APIC and store the session token."""
        login_domain = os.environ.get("APIC_LOGIN_DOMAIN", "LOCAL")
        payload = {
            "aaaUser": {
                "attributes": {
                    "name": f"apic#{login_domain}\\\\{self._user}",
                    "pwd": self._password,
                }
            }
        }
        resp = await self._client.post(
            f"{self.base_url}/api/aaaLogin.json", json=payload
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["imdata"][0]["aaaLogin"]["attributes"]["token"]
        self._client.cookies.set("APIC-cookie", self._token)

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """Make an authenticated request, re-authenticating on 401/403."""
        if self._token is None:
            await self.login()

        resp = await self._client.request(method, f"{self.base_url}{path}", **kwargs)

        if resp.status_code in (401, 403):
            await self.login()
            resp = await self._client.request(
                method, f"{self.base_url}{path}", **kwargs
            )

        resp.raise_for_status()
        return resp

    async def get_class_meta(self, class_name: str) -> dict:
        """Fetch JSON metadata for a given ACI class.

        Args:
            class_name: Full class name like 'fvTenant'. Will be split into
                        package prefix and class name for the URL path.

        Returns:
            Parsed JSON metadata dict.
        """
        pkg, name = self._split_class_name(class_name)
        path = f"/doc/jsonmeta/{pkg}/{name}.json"
        resp = await self._request("GET", path)
        return resp.json()

    async def get_class_overview(self, class_name: str) -> dict:
        """Fetch class overview data (alternative endpoint)."""
        # The model-doc app loads data from the same jsonmeta endpoint
        return await self.get_class_meta(class_name)

    async def list_objects(self) -> list[str]:
        """Fetch the list of all available MO class names from the APIC.

        Tries the documentation package index endpoint first, then falls
        back to querying the meta API.
        """
        try:
            resp = await self._request("GET", "/doc/jsonmeta/aci-meta.json")
            data = resp.json()
            # aci-meta.json typically has a "classes" key with all class names
            if isinstance(data, dict) and "classes" in data:
                return sorted(data["classes"].keys())
            # If it's a flat dict of class definitions
            if isinstance(data, dict):
                return sorted(data.keys())
        except (httpx.HTTPStatusError, KeyError):
            pass

        # Fallback: query the class API for a known subset
        try:
            resp = await self._request(
                "GET", "/api/class/pkiMeta.json?query-target-filter=wcard(pkiMeta.dn,\"\")"
            )
        except httpx.HTTPStatusError:
            pass

        # Last resort: return empty and let the tool handle it
        return []

    async def search_meta(self, keyword: str) -> list[dict]:
        """Search the full metadata index for classes matching a keyword."""
        try:
            resp = await self._request("GET", "/doc/jsonmeta/aci-meta.json")
            data = resp.json()
        except (httpx.HTTPStatusError, Exception):
            return []

        results = []
        classes = data.get("classes", data) if isinstance(data, dict) else {}

        keyword_lower = keyword.lower()
        for cls_name, cls_data in classes.items():
            searchable = cls_name.lower()
            if isinstance(cls_data, dict):
                label = cls_data.get("label", "")
                desc = cls_data.get("description", "")
                searchable = f"{cls_name} {label} {desc}".lower()

            if keyword_lower in searchable:
                results.append(
                    {
                        "className": cls_name,
                        "label": cls_data.get("label", "") if isinstance(cls_data, dict) else "",
                        "description": (
                            cls_data.get("description", "")
                            if isinstance(cls_data, dict)
                            else ""
                        ),
                    }
                )

        return results

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    @staticmethod
    def _split_class_name(class_name: str) -> tuple[str, str]:
        """Split an ACI class name into (package, ClassName).

        ACI classes follow the pattern: lowercase prefix + CamelCase name.
        Examples:
            fvTenant -> ('fv', 'Tenant')
            l3extOut -> ('l3ext', 'Out')
            infraAccPortP -> ('infra', 'AccPortP')
            vzBrCP -> ('vz', 'BrCP')
        """
        # Find the boundary: last lowercase char before first uppercase
        match = re.match(r"^([a-z0-9]+)([A-Z].*)$", class_name)
        if match:
            return match.group(1), match.group(2)
        # Fallback: treat entire thing as the name under root
        return "", class_name
