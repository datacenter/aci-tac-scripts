"""Tool: Search ACI object classes by keyword or description."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from aci_model_docs.tools.list_classes import KNOWN_CLASSES


async def search_classes(keyword: str, ctx: Context) -> str:
    """Search ACI managed object classes by keyword.

    Searches class names, labels, and descriptions for matches.
    Useful when you don't know the exact class name but know what
    you're looking for (e.g., 'bridge domain', 'contract', 'endpoint').

    Args:
        keyword: Search term (e.g., 'bridge domain', 'tenant', 'contract').
    """
    client = ctx.request_context.lifespan_context.client

    # Try live search from APIC metadata
    results = await client.search_meta(keyword)

    if results:
        lines = [f"## Search Results for '{keyword}' ({len(results)} matches)"]
        lines.append("")
        for r in results[:30]:  # Limit to 30 results
            name = r["className"]
            label = r.get("label", "")
            desc = r.get("description", "")
            line = f"- **`{name}`**"
            if label:
                line += f" — {label}"
            if desc:
                line += f": {desc[:100]}"
            lines.append(line)

        if len(results) > 30:
            lines.append(f"\n_...and {len(results) - 30} more matches._")

        lines.append("")
        lines.append("_Use `lookup_class` with a specific class name to get full details._")
        return "\n".join(lines)

    # Fallback: search the known classes list by name
    keyword_lower = keyword.lower()
    matches = []
    for pkg, classes in KNOWN_CLASSES.items():
        for cls in classes:
            if keyword_lower in cls.lower():
                matches.append(cls)

    if matches:
        lines = [f"## Search Results for '{keyword}' ({len(matches)} matches from known list)"]
        lines.append("_Note: Searched local known-classes list (APIC meta index unavailable)._")
        lines.append("")
        for cls in sorted(matches):
            lines.append(f"- `{cls}`")
        lines.append("")
        lines.append("_Use `lookup_class` with a specific class name to get full details._")
        return "\n".join(lines)

    return (
        f"No classes found matching '{keyword}'. "
        "Try a different search term or use `list_classes` to browse available classes."
    )
