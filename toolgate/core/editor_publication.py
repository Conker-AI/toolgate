"""Bridge visual documents into the existing immutable automation registry."""
from .editor_drafts import EditorDocument
from .editor_graph import validate_graph


def document_from_block(block):
    if set(block) != {"type", "document"} or block["type"] != "editor_graph":
        raise ValueError("Editor graph block requires only type and document.")
    document = EditorDocument.model_validate(block["document"])
    issues = validate_graph(document)
    if issues:
        raise ValueError(issues[0]["message"])
    # Credentials belong to the registered capability's runtime binding. A draft
    # cannot introduce a new vault binding merely by naming a connection.
    if document.credentialRefs:
        raise ValueError("Bind credentials on registered tools, not the editor graph.")
    return document


def dependency_steps(block):
    """All branches, including untaken paths, take part in publication review."""
    document = document_from_block(block)
    steps = []
    for node in document.nodes:
        config = node.config
        if node.type == "tool_call":
            steps.append({"type": "tool_call", "tool_id": config["tool"]})
        elif node.type == "workflow_call":
            steps.append({"type": "automation_call", "automation_id": config["toolId"],
                          "published_version": config["version"]})
        else:
            # Count computation nodes too, without treating their configuration
            # as the older structured-workflow language.
            steps.append({"type": "set"})
    return steps
