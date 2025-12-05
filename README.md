# CloneAndDeadCodeDetection

This repository provides a complete pipeline for converting Python code into a Neo4j graph and running static-analysis queries such as clone detection, unused variable detection, unused imports, and unreachable code identification.

This README focuses **only on running and testing the project**.  

## 1. Installation & Setup

### Start Neo4j

Use Neo4j Desktop or Neo4j Server at:

```
bolt://localhost:7687
```

### Set environment variables for Neo4j credentials

```bash
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=<your-password>
```

---

## 2. Running the Full Pipeline

The execution pipeline consists of two major steps.

---

### Step 1 — Bulk Ingest Python Files into Neo4j

```bash
python src/bulk_ingest.py /path/to/python/project
```

This step:

- Parses all `.py` files  
- Extracts AST nodes, functions, variables, imports, calls, control flows  
- Normalizes functions and computes structural hashes  
- Inserts everything into Neo4j  
- Marks unreachable AST nodes  

Example output:

```
=== BULK INGEST START ===
Found X Python files.
[INGEST] utils/helpers.py
[INGEST] app/core/handler.py
=== BULK INGEST COMPLETE ===
```

---

### Step 2 — Run Cross-Module Resolver

```bash
python src/resolver.py /path/to/python/project
```

This performs:

- Module name resolution  
- Mapping of variables to their defining modules  
- Resolving `from X import Y`  
- Resolving `module.CONST` usages  
- Creating cross-module `USES_VARIABLE` edges  

Output example:

```
[resolver] Mapped N files to module names.
[resolver] Collected module-level variables.
[resolver] Created RESOLVES_TO edges.
[resolver] Propagated variable usages.
[resolver] Done.
```

Your Neo4j graph is now ready for querying.

---

## 3. Querying Results in Neo4j Browser

Open the Neo4j Browser:

```
http://localhost:7474
```

---

### 3.1 Structural Clone Detection

```cypher
MATCH (f:Function)
WITH f.structural_hash AS hash, collect(f) AS funcs
WHERE size(funcs) > 1
RETURN hash, funcs;
```

---

### 3.2 Project-Wide Unused Variables

```cypher
MATCH (v:Variable)
WHERE NOT (v)<-[:USES_VARIABLE]-()
RETURN v.file_path, v.name, v.start_line
ORDER BY v.file_path, v.start_line;
```

---

### 3.3 Unused Imports

```cypher
MATCH (i:Import)
WHERE NOT (i)<-[:USES_IMPORT]-()
RETURN i.file_path, i.module, i.name, i.start_line;
```

---

### 3.4 Dead Functions (No Callers)

```cypher
MATCH (f:Function)
WHERE NOT ()-[:CALLS]->(f)
RETURN f.file_path, f.name, f.start_line;
```

---

### 3.5 Unreachable Code

```cypher
MATCH (n:AstNode)
WHERE n.is_unreachable = true
RETURN n.file_path, n.start_line, n.unreachable_reason;
```

---

## 4. Repository Structure

```
src/
 ├── ast_extractor.py       # AST parsing, normalization, unreachable code tagging
 ├── inject_to_neo4j.py     # Writes graph into Neo4j
 ├── bulk_ingest.py         # Recursively ingests an entire folder
 └── resolver.py            # Cross-module import + variable resolution
README.md
```

Diagrams and screenshots should be kept in a **separate supplementary file**.

---

## Evaluation Dataset
To test the effectiveness of our graph-based analysis, used the open-source Python repository:

(nvbn/thefuck): https://github.com/nvbn/thefuck

This repository provides a sufficiently complex module hierarchy and numerous repeated patterns
that allow us to evaluate clone detection, unused-variable detection, and unreachable code analysis.

