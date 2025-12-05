import os
import sys
from pathlib import Path
from inject_to_neo4j import ingest_file, create_constraints, driver

"""
Bulk ingestion script to load an entire Python project into Neo4j

"""

def ingest_folder(root_folder: str):
    root_folder = Path(root_folder)

    if not root_folder.exists():
        print(f"[ERROR] Folder does not exist: {root_folder}")
        sys.exit(1)

    print(f"\n=== BULK INGEST START ===")
    print(f"Project folder: {root_folder}\n")

    py_files = list(root_folder.rglob("*.py"))

    if not py_files:
        print("No .py files found.")
        sys.exit(1)

    print(f"Found {len(py_files)} Python files.\n")

    for f in py_files:
        try:
            print(f"[INGEST] {f}")
            ingest_file(driver, str(f))
        except Exception as e:
            print(f"[ERROR] While ingesting {f}: {e}")

    print("\n=== BULK INGEST COMPLETE ===")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python bulk_ingest.py <project_folder>")
        sys.exit(1)

    folder = sys.argv[1]

    create_constraints(driver)

    ingest_folder(folder)
