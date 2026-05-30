"""Tool: List available ACI object classes, optionally filtered by package."""

from __future__ import annotations

import os

from mcp.server.fastmcp import Context


# Well-known classes per package as fallback when the APIC index is unavailable
KNOWN_CLASSES: dict[str, list[str]] = {
    "fv": [
        "fvTenant", "fvAp", "fvAEPg", "fvBD", "fvCtx", "fvSubnet",
        "fvRsBd", "fvRsCtx", "fvRsDomAtt", "fvRsPathAtt", "fvRsProv",
        "fvRsCons", "fvCEp", "fvIp",
    ],
    "vz": [
        "vzBrCP", "vzSubj", "vzRsSubjFiltAtt", "vzFilter", "vzEntry",
        "vzAny", "vzOOBBrCP", "vzTaboo",
    ],
    "l3ext": [
        "l3extOut", "l3extLNodeP", "l3extLIfP", "l3extInstP", "l3extRsEctx",
        "l3extSubnet", "l3extRsNodeL3OutAtt", "l3extRsPathL3OutAtt",
        "l3extMember", "l3extIp",
    ],
    "infra": [
        "infraAccPortP", "infraNodeP", "infraFuncP", "infraRsAccBaseGrp",
        "infraAccBndlGrp", "infraHPortS", "infraPortBlk", "infraRsAccPortP",
        "infraAttEntityP", "infraRsDomP", "infraWiFiP",
    ],
    "fabric": [
        "fabricNode", "fabricPod", "fabricHIfPol", "fabricInst",
        "fabricProtPol", "fabricExplicitGEp", "fabricRsVpcInstPol",
        "fabricNodeIdentP",
    ],
}


async def list_classes(package_filter: str = "", ctx: Context = None) -> str:
    """List available ACI managed object classes.

    Can be filtered by package prefix (e.g., 'fv', 'vz', 'l3ext').
    If no filter is provided, returns classes from all configured packages.

    Args:
        package_filter: Optional package prefix to filter by (e.g., 'fv', 'vz').
                       Leave empty to list all configured packages.
    """
    client = ctx.request_context.lifespan_context.client

    # Determine which packages to show
    configured_packages = os.environ.get("APIC_PACKAGES", "").strip()
    if package_filter:
        allowed_packages = [package_filter.lower()]
    elif configured_packages:
        allowed_packages = [p.strip().lower() for p in configured_packages.split(",")]
    else:
        allowed_packages = None  # No filter — show all

    # Try live fetch from APIC
    all_classes = await client.list_objects()

    if all_classes:
        # Filter by package
        if allowed_packages:
            filtered = [
                c for c in all_classes
                if any(c.lower().startswith(pkg) for pkg in allowed_packages)
            ]
        else:
            filtered = all_classes

        if not filtered:
            return f"No classes found matching package filter: {package_filter or configured_packages}"

        lines = [f"## ACI Object Classes ({len(filtered)} found)"]
        if package_filter:
            lines[0] += f" — package: {package_filter}"
        lines.append("")

        # Group by package prefix
        grouped: dict[str, list[str]] = {}
        for cls in filtered:
            import re
            match = re.match(r"^([a-z0-9]+)[A-Z]", cls)
            pkg = match.group(1) if match else "other"
            grouped.setdefault(pkg, []).append(cls)

        for pkg in sorted(grouped.keys()):
            lines.append(f"### {pkg}*")
            for cls in sorted(grouped[pkg]):
                lines.append(f"- `{cls}`")
            lines.append("")

        return "\n".join(lines)

    # Fallback to known classes
    lines = ["## ACI Object Classes (from known list)"]
    lines.append("_Note: Could not fetch live index from APIC. Showing curated list._")
    lines.append("")

    packages_to_show = (
        {pkg: classes for pkg, classes in KNOWN_CLASSES.items() if pkg in allowed_packages}
        if allowed_packages
        else KNOWN_CLASSES
    )

    if not packages_to_show:
        return f"No known classes for package filter: {package_filter}"

    for pkg in sorted(packages_to_show.keys()):
        lines.append(f"### {pkg}*")
        for cls in sorted(packages_to_show[pkg]):
            lines.append(f"- `{cls}`")
        lines.append("")

    lines.append("---")
    lines.append("_To expand: set `APIC_PACKAGES` env var or pass a specific package filter._")

    return "\n".join(lines)
