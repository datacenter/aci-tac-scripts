"""Tool: Look up ACI class metadata (properties, relationships, DN format)."""

from __future__ import annotations

from mcp.server.fastmcp import Context


async def lookup_class(class_name: str, ctx: Context) -> str:
    """Look up full documentation for an ACI managed object class.

    Returns properties (name, type, description, default value),
    parent/child relationships, DN format, and REST API endpoint.

    Args:
        class_name: The ACI class name, e.g. 'fvTenant', 'fvBD', 'vzBrCP'.
    """
    client = ctx.request_context.lifespan_context.client

    try:
        meta = await client.get_class_meta(class_name)
    except Exception as e:
        return f"Error fetching metadata for '{class_name}': {e}"

    return _format_class_meta(class_name, meta)


def _format_class_meta(class_name: str, meta: dict) -> str:
    """Format raw JSON metadata into a readable summary.

    The APIC jsonmeta format uses:
    - Top-level key: 'pkg:ClassName' (e.g. 'fv:Tenant')
    - Fields: label, comment, dnFormats, rnFormat, properties, contains, containedBy
    - Properties: dict of {propName: {label, baseType, modelType, comment, isConfigurable,
                                      readOnly, mandatory, isNaming, ...}}
    - contains / containedBy: dict of {'pkg:ClassName': ''} for children/parents
    """
    lines: list[str] = []

    # The top-level key is in 'pkg:ClassName' colon notation
    class_data = next(iter(meta.values())) if meta else {}

    # Header
    label = class_data.get("label", class_name)
    comment = class_data.get("comment", [])
    description = comment[0] if isinstance(comment, list) and comment else (
        comment if isinstance(comment, str) else ""
    )

    lines.append(f"# {class_name}")
    if label and label != class_name:
        lines.append(f"**Label**: {label}")
    if description:
        lines.append(f"**Description**: {description}")
    lines.append("")

    # DN / RN format
    dn_formats = class_data.get("dnFormats", [])
    rn_format = class_data.get("rnFormat", "")
    if dn_formats or rn_format:
        lines.append("## DN / RN Format")
        for dn in (dn_formats if isinstance(dn_formats, list) else [dn_formats]):
            lines.append(f"- DN: `{dn}`")
        if rn_format:
            lines.append(f"- RN: `{rn_format}`")
        lines.append("")

    # REST API endpoints
    lines.append("## REST API")
    lines.append(f"- Class query: `GET /api/class/{class_name}.json`")
    lines.append(f"- DN query:    `GET /api/mo/{{dn}}.json`")
    lines.append("")

    # Properties — skip implicit/internal ones by default, show configurable ones first
    properties: dict = class_data.get("properties", {})
    if properties:
        configurable = {k: v for k, v in properties.items()
                        if isinstance(v, dict) and v.get("isConfigurable")}
        readonly = {k: v for k, v in properties.items()
                    if isinstance(v, dict) and not v.get("isConfigurable")
                    and not v.get("implicit")}

        def prop_rows(props: dict) -> list[str]:
            rows = []
            for prop_name, pd in props.items():
                if not isinstance(pd, dict):
                    continue
                ptype = pd.get("modelType", pd.get("baseType", ""))
                pdesc_raw = pd.get("comment", [])
                pdesc = pdesc_raw[0] if isinstance(pdesc_raw, list) and pdesc_raw else (
                    pdesc_raw if isinstance(pdesc_raw, str) else ""
                )
                mandatory = " *(required)*" if pd.get("mandatory") else ""
                naming = " *(naming)*" if pd.get("isNaming") else ""
                rows.append(f"| `{prop_name}` | `{ptype}` | {pdesc}{mandatory}{naming} |")
            return rows

        if configurable:
            lines.append("## Configurable Properties")
            lines.append("")
            lines.append("| Name | Type | Description |")
            lines.append("|------|------|-------------|")
            lines.extend(prop_rows(configurable))
            lines.append("")

        if readonly:
            lines.append("## Read-Only Properties")
            lines.append("")
            lines.append("| Name | Type | Description |")
            lines.append("|------|------|-------------|")
            lines.extend(prop_rows(readonly))
            lines.append("")

    # Children (contains)
    children = class_data.get("contains", {})
    if children and isinstance(children, dict):
        lines.append(f"## Children ({len(children)} classes)")
        for child_cls in sorted(children.keys()):
            lines.append(f"- `{child_cls}`")
        lines.append("")

    # Parents (containedBy)
    parents = class_data.get("containedBy", {})
    if parents and isinstance(parents, dict):
        lines.append(f"## Parents ({len(parents)} classes)")
        for parent_cls in sorted(parents.keys()):
            lines.append(f"- `{parent_cls}`")
        lines.append("")

    return "\n".join(lines)
