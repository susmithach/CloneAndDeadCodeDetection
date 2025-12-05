#!/usr/bin/env python3
"""
resolver.py

Post-ingestion resolver that adds *cross-module* variable usage edges in Neo4j.

Pipeline:

    python bulk_ingest.py /path/to/project
    python resolver.py /path/to/project

"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Tuple, Optional, List

from neo4j import GraphDatabase
from inject_to_neo4j import driver 


# --------- Helpers / Data Classes ---------

@dataclass
class VariableDef:
    module: str
    name: str
    file_path: str
    node_id: int


@dataclass
class ImportBinding:
    file_path: str
    node_id: int
    module: str 
    name: str   

@dataclass
class AttributeUse:
    file_path: str
    node_id: int
    text: str


def compute_module_name(file_path: str, project_root: Path) -> Optional[str]:
    """
    Derive a Python-style module name from a file path, relative to project_root.

    Examples:
        /proj/conf.py                -> "conf"
        /proj/utils/helpers.py       -> "utils.helpers"
        /proj/app/__init__.py        -> "app"
        /proj/app/core/handlers.py   -> "app.core.handlers"
    """
    try:
        abs_root = project_root.resolve()
        abs_file = Path(file_path).resolve()
        rel = os.path.relpath(abs_file, abs_root)
    except Exception:
        return None

    rel = rel.replace("\\", "/")

    if not rel.endswith(".py"):
        return None

    rel_no_ext = rel[:-3]  

    # Handle __init__.py as package module
    if rel_no_ext.endswith("/__init__"):
        rel_no_ext = rel_no_ext[: -len("/__init__")]

    rel_no_ext = rel_no_ext.strip("/")

    if not rel_no_ext:
        # Top-level __init__.py (rare): treat as root package
        return None

    return rel_no_ext.replace("/", ".")


def parse_attribute_chain(text: str) -> Optional[List[str]]:

    if not text:
        return None

    token = text.strip().split()[0]

    # Bail out if it looks like a call/index/etc.
    if any(ch in token for ch in ("(", ")", "[", "]", ",")):
        return None

    parts = token.split(".")
    if len(parts) < 2:
        return None

    # All segments should be valid identifiers.
    if not all(p.isidentifier() for p in parts):
        return None

    return parts


# --------- Resolver Logic ---------

def build_file_module_map(session, project_root: Path) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Returns:
        path_to_module: file_path -> module_name
        module_to_path: module_name -> file_path
    """
    path_to_module: Dict[str, str] = {}
    module_to_path: Dict[str, str] = {}

    result = session.run("MATCH (f:File) RETURN f.path AS path")
    rows = list(result)

    for row in rows:
        path = row["path"]
        mod = compute_module_name(path, project_root)
        if not mod:
            continue
        path_to_module[path] = mod
        module_to_path[mod] = path

    # annotate File nodes with module_name
    if rows:
        session.run("""
            UNWIND $rows AS row
            MATCH (f:File {path: row.path})
            SET f.module_name = row.module
        """, rows=[{"path": p, "module": m} for p, m in path_to_module.items()])

    print(f"[resolver] Mapped {len(path_to_module)} files to module names.")
    return path_to_module, module_to_path


def build_global_variables(session, path_to_module: Dict[str, str]) -> Dict[str, Dict[str, VariableDef]]:
    """
    Only includes module-level variables
    """
    vars_by_module: Dict[str, Dict[str, VariableDef]] = {}

    result = session.run("""
        MATCH (v:Variable)
        WHERE v.defined_in_function IS NULL
        RETURN v.file_path AS file_path,
               v.name AS name,
               v.node_id AS node_id
    """)

    count = 0
    for row in result:
        file_path = row["file_path"]
        name = row["name"]
        node_id = row["node_id"]

        mod = path_to_module.get(file_path)
        if not mod:
            continue

        mod_map = vars_by_module.setdefault(mod, {})
        if name in mod_map:
            continue

        mod_map[name] = VariableDef(
            module=mod,
            name=name,
            file_path=file_path,
            node_id=node_id,
        )
        count += 1

    print(f"[resolver] Collected {count} module-level variables across {len(vars_by_module)} modules.")
    return vars_by_module


def load_imports(session) -> List[ImportBinding]:
    """
    Load all Import nodes.
    """
    result = session.run("""
        MATCH (i:Import)
        RETURN i.file_path AS file_path,
               i.node_id AS node_id,
               i.module AS module,
               i.name AS name
    """)
    imports: List[ImportBinding] = []
    for row in result:
        imports.append(ImportBinding(
            file_path=row["file_path"],
            node_id=row["node_id"],
            module=row["module"] or "",
            name=row["name"],
        ))
    print(f"[resolver] Loaded {len(imports)} Import bindings.")
    return imports


def load_attributes(session) -> List[AttributeUse]:
    """
    Load all Attribute AstNodes
    """
    result = session.run("""
        MATCH (n:AstNode)
        WHERE n.type = "Attribute"
        RETURN n.file_path AS file_path,
               n.node_id AS node_id,
               n.text AS text
    """)
    attrs: List[AttributeUse] = []
    for row in result:
        attrs.append(AttributeUse(
            file_path=row["file_path"],
            node_id=row["node_id"],
            text=row["text"] or "",
        ))
    print(f"[resolver] Loaded {len(attrs)} Attribute nodes.")
    return attrs


def resolve_from_imports(session,
                         imports: List[ImportBinding],
                         vars_by_module: Dict[str, Dict[str, VariableDef]]):
    
    mappings = []

    for imp in imports:
        module_name = imp.module.strip()
        if not module_name:
            # Probably relative import like "from . import X" – skip for now
            continue

        # Direct: from module import CONST
        mod_vars = vars_by_module.get(module_name)
        if not mod_vars:
            continue

        var_def = mod_vars.get(imp.name)
        if not var_def:
            continue

        mappings.append({
            "imp_file": imp.file_path,
            "imp_node": imp.node_id,
            "var_file": var_def.file_path,
            "var_node": var_def.node_id,
        })

    if not mappings:
        print("[resolver] No direct from-import variable mappings found.")
        return

    session.run("""
        UNWIND $rows AS row
        MATCH (i:Import {
            file_path: row.imp_file,
            node_id: row.imp_node
        })
        MATCH (v:Variable {
            file_path: row.var_file,
            node_id: row.var_node
        })
        MERGE (i)-[:RESOLVES_TO]->(v)
    """, rows=mappings)

    print(f"[resolver] Created {len(mappings)} (Import)-[:RESOLVES_TO]->(Variable) edges for from-imports.")


def propagate_name_usages(session):
    """
    For all Name-based usages of imports that have been resolved to variables,
    create a :USES_VARIABLE edge:
    """
    session.run("""
        MATCH (use:AstNode)-[:USES_IMPORT]->(i:Import)-[:RESOLVES_TO]->(v:Variable)
        MERGE (use)-[:USES_VARIABLE]->(v)
    """)

    result2 = session.run("""
        MATCH (use:AstNode)-[:USES_IMPORT]->(i:Import)-[:RESOLVES_TO]->(v:Variable)
        RETURN count(use) AS cnt
    """)
    cnt_after = result2.single()["cnt"]

    print(f"[resolver] Propagated Name-based import usages to variables "
          f"({cnt_after} total use->var candidates).")


def resolve_attribute_usages(session,
                             attrs: List[AttributeUse],
                             imports: List[ImportBinding],
                             vars_by_module: Dict[str, Dict[str, VariableDef]],
                             module_to_path: Dict[str, str]):

    # Build imports_by_file: file_path -> { binding_name -> effective_module_name }
    imports_by_file: Dict[str, Dict[str, str]] = {}

    for imp in imports:
        per_file = imports_by_file.setdefault(imp.file_path, {})

        module_name = (imp.module or "").strip()
        if not module_name:
            # Skip relative-only imports for now
            continue

        effective_module = module_name

        candidate_full = f"{module_name}.{imp.name}"
        if candidate_full in module_to_path:
            effective_module = candidate_full

        if imp.name not in per_file:
            per_file[imp.name] = effective_module

    mappings = []

    for attr in attrs:
        chain = parse_attribute_chain(attr.text)
        if not chain:
            continue

        base = chain[0]
        var_name = chain[-1]

        per_file = imports_by_file.get(attr.file_path)
        if not per_file:
            continue

        module_name = per_file.get(base)
        if not module_name:
            continue

        mod_vars = vars_by_module.get(module_name)
        if not mod_vars:
            continue

        var_def = mod_vars.get(var_name)
        if not var_def:
            continue

        mappings.append({
            "use_file": attr.file_path,
            "use_node": attr.node_id,
            "var_file": var_def.file_path,
            "var_node": var_def.node_id,
        })

    if not mappings:
        print("[resolver] No attribute-based module alias usages resolved.")
        return

    session.run("""
        UNWIND $rows AS row
        MATCH (use:AstNode {
            file_path: row.use_file,
            node_id: row.use_node
        })
        MATCH (v:Variable {
            file_path: row.var_file,
            node_id: row.var_node
        })
        MERGE (use)-[:USES_VARIABLE]->(v)
    """, rows=mappings)

    print(f"[resolver] Created {len(mappings)} attribute-based (AstNode)-[:USES_VARIABLE]->(Variable) edges.")


def main():
    if len(sys.argv) < 2:
        print("Usage: python resolver.py <project_root>")
        sys.exit(1)

    project_root = Path(sys.argv[1]).resolve()
    if not project_root.exists():
        print(f"[ERROR] Project root does not exist: {project_root}")
        sys.exit(1)

    print(f"[resolver] Project root: {project_root}")

    with driver.session() as session:
        # 1) Build mapping: file_path -> module_name, module_name -> file_path
        path_to_module, module_to_path = build_file_module_map(session, project_root)

        # 2) Build global module-level variables map
        vars_by_module = build_global_variables(session, path_to_module)

        # 3) Load imports and attributes
        imports = load_imports(session)
        attrs = load_attributes(session)

        # 4) Resolve direct "from module import CONST" imports
        resolve_from_imports(session, imports, vars_by_module)

        # 5) Propagate Name-based usages through :RESOLVES_TO
        propagate_name_usages(session)

        # 6) Resolve attribute-based module.alias.CONST patterns (A, B, C, D)
        resolve_attribute_usages(session, attrs, imports, vars_by_module, module_to_path)

    print("[resolver] Done. You can now query unused variables across the project.\n")
    print("Example Cypher to list unused variables:")
    print("""
    MATCH (v:Variable)
    WHERE NOT (v)<-[:USES_VARIABLE]-()
    RETURN v.file_path AS file, v.name AS name, v.start_line AS line
    ORDER BY file, line
    """)


if __name__ == "__main__":
    main()
