# inject_to_neo4j.py

from neo4j import GraphDatabase
from pathlib import Path

from ast_extractor import (
    CodeGraphExtractor,
    FileAnalysis,
    AstNodeInfo,
    FunctionInfo,
    ImportInfo,
    VariableInfo,
    ControlFlowInfo,
    CallInfo,
    ImportUsageInfo,
    VariableUsageInfo,
    UnreachableInfo,
)

# ---------------- Neo4j Connection ----------------

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "password"

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


# ---------------- Constraints ----------------

def create_constraints(driver):
    with driver.session() as s:

        # File unique
        s.run("""
            CREATE CONSTRAINT IF NOT EXISTS
            FOR (f:File) REQUIRE f.path IS UNIQUE
        """)

        # Function unique per file
        s.run("""
            CREATE CONSTRAINT IF NOT EXISTS
            FOR (fn:Function) REQUIRE (fn.file_path, fn.name) IS UNIQUE
        """)

        # AstNode unique
        s.run("""
            CREATE CONSTRAINT IF NOT EXISTS
            FOR (a:AstNode) REQUIRE (a.file_path, a.node_id) IS UNIQUE
        """)

        # Import unique PER (file_path, name)
        s.run("""
            CREATE CONSTRAINT IF NOT EXISTS
            FOR (i:Import) REQUIRE (i.file_path, i.name) IS UNIQUE
        """)


# ---------------- Ingestion Helpers ----------------

def _create_file(tx, file_path: str):
    tx.run("MERGE (f:File {path: $path})", path=file_path)


def _create_ast_nodes(tx, file_path: str, ast_nodes):
    for n in ast_nodes:
        tx.run("""
            MERGE (a:AstNode {
                file_path: $file_path,
                node_id: $node_id
            })
            SET a.type = $type,
                a.text = $text,
                a.start_line = $start_line,
                a.end_line = $end_line
        """, file_path=file_path, node_id=n.node_id,
             type=n.type, text=n.text,
             start_line=n.start_line, end_line=n.end_line)

        # children edges
        for c in n.children_ids:
            tx.run("""
                MATCH (p:AstNode {file_path: $file_path, node_id: $parent})
                MATCH (c:AstNode {file_path: $file_path, node_id: $child})
                MERGE (p)-[:CHILD]->(c)
            """, file_path=file_path, parent=n.node_id, child=c)


def _create_functions(tx, file_path: str, functions):
    for fn in functions:
        tx.run("""
            MATCH (f:File {path: $file_path})
            MATCH (root:AstNode {file_path: $file_path, node_id: $node_id})

            MERGE (fn:Function {
                file_path: $file_path,
                name: $name
            })
            SET fn.start_line = $start_line,
                fn.end_line = $end_line,
                fn.parameters = $params,
                fn.normalized_body = $norm,
                fn.structural_hash = $hash

            MERGE (f)-[:CONTAINS]->(fn)
            MERGE (fn)-[:AST_ROOT]->(root)
        """, file_path=file_path,
             name=fn.name, node_id=fn.node_id,
             start_line=fn.start_line, end_line=fn.end_line,
             params=fn.parameters,
             norm=fn.normalized_body,
             hash=fn.structural_hash)


# --------- IMPORT INGESTION ---------

def _create_imports(tx, file_path: str, imports):
    for imp in imports:
        tx.run("""
            MERGE (i:Import {
                file_path: $file_path,
                name: $name
            })
            SET i.module = $module,
                i.start_line = $start_line,
                i.node_id = $node_id

            WITH i
            MATCH (f:File {path: $file_path})
            MERGE (f)-[:HAS_IMPORT]->(i)
        """, file_path=file_path,
             name=imp.name,
             module=imp.module,
             start_line=imp.start_line,
             node_id=imp.node_id)


def _create_variables(tx, file_path: str, variables):
    for v in variables:
        tx.run("""
            MERGE (var:Variable {
                file_path: $file_path,
                node_id: $node_id
            })
            SET var.name = $name,
                var.defined_in_function = $func,
                var.start_line = $line

            WITH var
            MATCH (f:File {path: $file_path})
            MERGE (f)-[:DECLARES_VAR]->(var)
        """, file_path=file_path,
             node_id=v.node_id,
             name=v.name,
             func=v.defined_in_function,
             line=v.start_line)


def _create_control_flows(tx, file_path: str, cf_list):
    for cf in cf_list:
        tx.run("""
            MERGE (c:ControlFlow {
                file_path: $file_path,
                node_id: $node_id
            })
            SET c.kind = $kind,
                c.start_line = $start,
                c.end_line = $end,
                c.parent_function = $parent

            WITH c
            MATCH (fn:Function {
                file_path: $file_path,
                name: $parent
            })
            MERGE (fn)-[:HAS_CF]->(c)
        """, file_path=file_path,
             node_id=cf.node_id,
             kind=cf.kind,
             start=cf.start_line,
             end=cf.end_line,
             parent=cf.parent_function)


def _create_calls(tx, file_path: str, calls):
    for c in calls:
        tx.run("""
            MATCH (caller:Function {file_path: $file_path, name: $caller})
            MATCH (callee:Function {file_path: $file_path, name: $callee})
            MERGE (caller)-[:CALLS {line: $line}]->(callee)
        """, file_path=file_path,
             caller=c.caller,
             callee=c.callee,
             line=c.line)


def _create_import_usages(tx, file_path: str, usages):
    for u in usages:
        tx.run("""
            MATCH (use:AstNode {file_path: $file_path, node_id: $user})
            MATCH (imp:Import {file_path: $file_path, name: $symbol})
            MERGE (use)-[:USES_IMPORT]->(imp)
        """, file_path=file_path,
             user=u.user_node_id,
             symbol=u.symbol)


def _create_variable_usages(tx, file_path: str, usages):
    for u in usages:
        tx.run("""
            MATCH (use:AstNode {file_path: $file_path, node_id: $user})
            MATCH (v:Variable {file_path: $file_path, node_id: $var})
            MERGE (use)-[:USES_VARIABLE]->(v)
        """, file_path=file_path,
             user=u.user_node_id,
             var=u.variable_node_id)


def _mark_unreachable(tx, file_path: str, unreachable):
    for u in unreachable:
        tx.run("""
            MATCH (n:AstNode {file_path: $file_path, node_id: $nid})
            SET n.is_unreachable = true,
                n.unreachable_reason = $reason
        """, file_path=file_path,
             nid=u.node_id,
             reason=u.reason)


# ---------------- Ingestion ----------------

def ingest_file(driver, file_path: str):
    extractor = CodeGraphExtractor()
    analysis = extractor.extract_from_file(file_path)

    with driver.session() as s:
        s.execute_write(_tx_ingest, analysis)


def _tx_ingest(tx, a: FileAnalysis):
    fp = a.file_path

    _create_file(tx, fp)
    _create_ast_nodes(tx, fp, a.ast_nodes)
    _create_functions(tx, fp, a.functions)
    _create_imports(tx, fp, a.imports)
    _create_variables(tx, fp, a.variables)
    _create_control_flows(tx, fp, a.control_flows)
    _create_calls(tx, fp, a.calls)
    _create_import_usages(tx, fp, a.import_usages)
    _create_variable_usages(tx, fp, a.variable_usages)
    _mark_unreachable(tx, fp, a.unreachable)


# ---------------- CLI ----------------

def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python inject_to_neo4j.py <file.py>")
        exit(1)

    file_path = sys.argv[1]
    print(f"Ingesting {file_path}...")
    ingest_file(driver, file_path)
    print("Done.")


if __name__ == "__main__":
    create_constraints(driver)
    main()
