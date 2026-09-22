"""Owner editor metadata: registered capabilities, never executor or vault data."""
import json

from . import control_plane as cp, publications


def list_capabilities(kind, query="", after=None, limit=50):
    # Use a cursor over registry identities; a workflow row is its newest
    # publication, not a mutable draft masquerading as executable.
    with cp._conn() as conn:
        if kind == "tool":
            rows = conn.execute("SELECT id,body FROM v2_objects WHERE kind='tool' AND id>? ORDER BY id",
                                (after or "",))
        else:
            rows = conn.execute("SELECT id,body FROM v2_publications p WHERE kind='automation' AND id>? "
                "AND version=(SELECT MAX(version) FROM v2_publications WHERE kind=p.kind AND id=p.id) ORDER BY id",
                (after or "",))
        items = []
        for row in rows:
            body = json.loads(row["body"])
            definition = body if kind == "tool" else body["definition"]
            if definition.get("status") != "active" or definition.get("authorization") == "blocked":
                continue
            name = str(definition.get("name") or row["id"])[:160]
            description = str(definition.get("description", ""))[:800]
            if query.casefold() not in f"{row['id']} {name} {description}".casefold():
                continue
            if kind != "tool":
                try:
                    publications.for_execution(conn, "automation", row["id"], body["version"])
                except publications.PublicationInvalid:
                    continue
            inputs = [{"name": str(field.get("name", ""))[:200],
                       "type": str(field.get("type", "string"))[:40],
                       "required": bool(field.get("required", False)),
                       "description": str(field.get("description", ""))[:500]}
                      for field in definition.get("inputs", [])[:100] if isinstance(field, dict)]
            items.append({"id": row["id"], "name": name, "description": description,
                          "inputs": inputs, "version": definition.get("version", 1),
                          "authorization": definition.get("authorization", "auto")})
            if len(items) > limit:
                break
        return {"items": items[:limit], "next_after": items[limit - 1]["id"] if len(items) > limit else None}
