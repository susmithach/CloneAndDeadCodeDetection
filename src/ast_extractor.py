from __future__ import annotations

import ast
import json
import hashlib
import itertools
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Dict, Optional, Tuple


# ---------- Data Models ----------

@dataclass
class AstNodeInfo:
    node_id: int
    type: str
    text: str
    start_line: int
    end_line: int
    parent_id: Optional[int]
    children_ids: List[int]


@dataclass
class FunctionInfo:
    name: str
    start_line: int
    end_line: int
    node_id: int
    parameters: List[str]
    normalized_body: str
    structural_hash: str


@dataclass
class ImportInfo:
    module: str
    name: str
    start_line: int
    node_id: int


@dataclass
class VariableInfo:
    name: str
    module: str | None      
    defined_in_function: Optional[str]
    start_line: int
    node_id: int


@dataclass
class ControlFlowInfo:
    kind: str
    start_line: int
    end_line: int
    node_id: int
    parent_function: Optional[str]


@dataclass
class CallInfo:
    caller: str
    callee: str
    line: int


@dataclass
class ImportUsageInfo:
    import_node_id: int
    user_node_id: int
    symbol: str
    in_function: Optional[str]
    line: int


@dataclass
class VariableUsageInfo:
    variable_node_id: int
    user_node_id: int
    name: str
    in_function: Optional[str]
    line: int


@dataclass
class UnreachableInfo:
    node_id: int
    reason: str


@dataclass
class FileAnalysis:
    file_path: str
    ast_nodes: List[AstNodeInfo]
    functions: List[FunctionInfo]
    imports: List[ImportInfo]
    variables: List[VariableInfo]
    control_flows: List[ControlFlowInfo]
    calls: List[CallInfo]
    import_usages: List[ImportUsageInfo]
    variable_usages: List[VariableUsageInfo]
    unreachable: List[UnreachableInfo]


# ---------- Normalization Engine (for clones) ----------

class FunctionNormalizer:

    def normalize_function(self, func_node: ast.AST) -> str:
        lines: List[str] = []
        for stmt in func_node.body:
            norm = self._norm_stmt(stmt, indent=0)
            if norm:
                lines.append(norm)
        return "\n".join(lines)

    # ---------- Statements ----------

    def _norm_stmt(self, node: ast.AST, indent: int) -> str:
        pad = "  " * indent

        # Simple assignments
        if isinstance(node, ast.Assign):
            targets = ", ".join(self._norm_expr(t) for t in node.targets)
            value = self._norm_expr(node.value)
            return f"{pad}ASSIGN {targets} = {value}"

        if isinstance(node, ast.AugAssign):
            target = self._norm_expr(node.target)
            value = self._norm_expr(node.value)
            op = self._norm_op(node.op)
            return f"{pad}AUGASSIGN {target} {op}= {value}"

        if isinstance(node, ast.AnnAssign):
            target = self._norm_expr(node.target)
            value = self._norm_expr(node.value) if node.value else "NONE"
            return f"{pad}ANNASSIGN {target} = {value}"

        # Returns
        if isinstance(node, ast.Return):
            value = self._norm_expr(node.value) if node.value else "NONE"
            return f"{pad}RETURN {value}"

        # Bare expression statement
        if isinstance(node, ast.Expr):
            return f"{pad}EXPR {self._norm_expr(node.value)}"

        # If / else
        if isinstance(node, ast.If):
            test = self._norm_expr(node.test)
            body_lines = [self._norm_stmt(s, indent + 1) for s in node.body]
            orelse_lines = [self._norm_stmt(s, indent + 1) for s in node.orelse]
            body_block = "\n".join(body_lines) if body_lines else f"{pad}  PASS"
            orelse_block = "\n".join(orelse_lines) if orelse_lines else f"{pad}  PASS"
            return f"{pad}IF {test}:\n{body_block}\n{pad}ELSE:\n{orelse_block}"

        # For loops
        if isinstance(node, ast.For):
            target = self._norm_expr(node.target)
            it = self._norm_expr(node.iter)
            body_lines = [self._norm_stmt(s, indent + 1) for s in node.body]
            body_block = "\n".join(body_lines) if body_lines else f"{pad}  PASS"
            return f"{pad}FOR {target} IN {it}:\n{body_block}"

        # While loops
        if isinstance(node, ast.While):
            test = self._norm_expr(node.test)
            body_lines = [self._norm_stmt(s, indent + 1) for s in node.body]
            body_block = "\n".join(body_lines) if body_lines else f"{pad}  PASS"
            return f"{pad}WHILE {test}:\n{body_block}"

        # Try/except/finally
        if isinstance(node, ast.Try):
            body_lines = [self._norm_stmt(s, indent + 1) for s in node.body]
            body_block = "\n".join(body_lines) if body_lines else f"{pad}  PASS"
            parts = [f"{pad}TRY:\n{body_block}"]
            for handler in node.handlers:
                htype = self._norm_expr(handler.type) if handler.type else "EXCEPTION"
                hbody_lines = [self._norm_stmt(s, indent + 1) for s in handler.body]
                hbody_block = "\n".join(hbody_lines) if hbody_lines else f"{pad}  PASS"
                parts.append(f"{pad}EXCEPT {htype}:\n{hbody_block}")
            if node.finalbody:
                fbody_lines = [self._norm_stmt(s, indent + 1) for s in node.finalbody]
                fbody_block = "\n".join(fbody_lines) if fbody_lines else f"{pad}  PASS"
                parts.append(f"{pad}FINALLY:\n{fbody_block}")
            return "\n".join(parts)

        # With
        if isinstance(node, ast.With):
            items = ", ".join(self._norm_expr(i.context_expr) for i in node.items)
            body_lines = [self._norm_stmt(s, indent + 1) for s in node.body]
            body_block = "\n".join(body_lines) if body_lines else f"{pad}  PASS"
            return f"{pad}WITH {items}:\n{body_block}"

        # Simple control statements
        if isinstance(node, (ast.Pass, ast.Break, ast.Continue)):
            return f"{pad}{type(node).__name__.upper()}"

        # Raise
        if isinstance(node, ast.Raise):
            exc = self._norm_expr(node.exc) if node.exc else "NONE"
            return f"{pad}RAISE {exc}"

        # Fallback: keep the statement type name
        return f"{pad}STMT_{type(node).__name__}"

    # ---------- Expressions ----------

    def _norm_expr(self, node: Optional[ast.AST]) -> str:
        if node is None:
            return "NONE"

        # Variable names → completely abstracted
        if isinstance(node, ast.Name):
            return "VAR"

        # Constants
        if isinstance(node, ast.Constant):
            v = node.value
            # Strings: keep exact
            if isinstance(v, str):
                # repr ensures quotes are part of the signature
                return f"STR:{repr(v)}"
            # Numbers: keep exact numeric text
            if isinstance(v, (int, float, complex)):
                return f"NUM:{repr(v)}"
            # Bool
            if isinstance(v, bool):
                return f"BOOL:{v}"
            # None
            if v is None:
                return "CONST_NONE"
            # Other constants
            return f"CONST:{type(v).__name__}:{repr(v)}"

        # Calls
        if isinstance(node, ast.Call):
            # Attribute call: obj.method(...)
            if isinstance(node.func, ast.Attribute):
                obj_norm = self._norm_expr(node.func.value)
                attr = node.func.attr
                args = ", ".join(self._norm_expr(a) for a in node.args)
                # e.g. STR:' && '.ATTR_join(VAR) vs STR:'; and '.ATTR_join(VAR)
                return f"{obj_norm}.ATTR_{attr}({args})"

            # Simple function call: func(...)
            if isinstance(node.func, ast.Name):
                callee = node.func.id
                args = ", ".join(self._norm_expr(a) for a in node.args)
                return f"CALL_{callee}({args})"

            # Fallback
            args = ", ".join(self._norm_expr(a) for a in node.args)
            return f"CALL_UNKNOWN({args})"

        # Binary operations
        if isinstance(node, ast.BinOp):
            left = self._norm_expr(node.left)
            right = self._norm_expr(node.right)
            op = self._norm_op(node.op)
            return f"BINOP_{op}({left}, {right})"

        # Unary operations
        if isinstance(node, ast.UnaryOp):
            operand = self._norm_expr(node.operand)
            op = self._norm_op(node.op)
            return f"UNARY_{op}({operand})"

        # Boolean operations
        if isinstance(node, ast.BoolOp):
            op = "AND" if isinstance(node.op, ast.And) else "OR"
            values = ", ".join(self._norm_expr(v) for v in node.values)
            return f"BOOL_{op}({values})"

        # Comparisons
        if isinstance(node, ast.Compare):
            left = self._norm_expr(node.left)
            ops = "_".join(self._norm_cmp_op(o) for o in node.ops)
            comps = ", ".join(self._norm_expr(c) for c in node.comparators)
            return f"COMPARE_{ops}({left}, {comps})"

        # Attributes
        if isinstance(node, ast.Attribute):
            value = self._norm_expr(node.value)
            return f"{value}.ATTR_{node.attr}"

        # Collections
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            elts = ", ".join(self._norm_expr(e) for e in node.elts)
            kind = type(node).__name__.upper()
            return f"{kind}({elts})"

        # Dict
        if isinstance(node, ast.Dict):
            keys = ", ".join(self._norm_expr(k) for k in node.keys)
            vals = ", ".join(self._norm_expr(v) for v in node.values)
            return f"DICT({keys} -> {vals})"

        # Subscript
        if isinstance(node, ast.Subscript):
            value = self._norm_expr(node.value)
            sl = self._norm_expr(node.slice)
            return f"SUBSCRIPT({value}[{sl}])"

        # Fallback: expression type name
        return f"EXPR_{type(node).__name__}"

    # ---------- Helpers ----------

    def _norm_op(self, op: ast.AST) -> str:
        return type(op).__name__.upper()

    def _norm_cmp_op(self, op: ast.cmpop) -> str:
        return type(op).__name__.upper()


# ---------- Extractor Class ----------

class CodeGraphExtractor:
    def __init__(self) -> None:
        self._id_counter = itertools.count(1)
        self._normalizer = FunctionNormalizer()

    def _next_id(self) -> int:
        return next(self._id_counter)

    def extract_from_file(self, path: str | Path) -> FileAnalysis:
        path = Path(path)
        module_name = path.stem  
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        ast_nodes: Dict[int, AstNodeInfo] = {}
        functions: List[FunctionInfo] = []
        imports: List[ImportInfo] = []
        variables: List[VariableInfo] = []
        control_flows: List[ControlFlowInfo] = []
        calls: List[CallInfo] = []
        import_usages: List[ImportUsageInfo] = []
        variable_usages: List[VariableUsageInfo] = []

        function_stack: List[str] = []
        ast_to_id: Dict[ast.AST, int] = {}

        import_by_symbol: Dict[str, ImportInfo] = {}
        variables_by_key: Dict[Tuple[str, Optional[str], str | None], VariableInfo] = {}

        def get_text(node: ast.AST) -> str:
            try:
                return ast.get_source_segment(source, node) or ""
            except Exception:
                return ""

        def get_lines(node: ast.AST):
            return getattr(node, "lineno", 0), getattr(node, "end_lineno", 0)

        # ---------- MAIN AST TRAVERSAL ----------

        def traverse(node: ast.AST, parent_id: Optional[int] = None) -> int:
            node_id = self._next_id()
            sl, el = get_lines(node)
            txt = get_text(node)

            ast_nodes[node_id] = AstNodeInfo(
                node_id=node_id,
                type=type(node).__name__,
                text=txt,
                start_line=sl,
                end_line=el,
                parent_id=parent_id,
                children_ids=[]
            )
            ast_to_id[node] = node_id

            if parent_id is not None:
                ast_nodes[parent_id].children_ids.append(node_id)

            # ------- FUNCTION -------
            if isinstance(node, ast.FunctionDef):
                norm = self._normalizer.normalize_function(node)
                fn = FunctionInfo(
                    name=node.name,
                    start_line=sl,
                    end_line=el,
                    node_id=node_id,
                    parameters=[a.arg for a in node.args.args],
                    normalized_body=norm,
                    structural_hash=hashlib.sha256(norm.encode()).hexdigest()
                )
                functions.append(fn)
                function_stack.append(node.name)

            # ------- IMPORT -------
            if isinstance(node, ast.Import):
                for alias in node.names:
                    full_name = alias.name             
                    binding = alias.asname or full_name.split('.')[0]

                    imp = ImportInfo(
                        module=full_name,
                        name=binding,
                        start_line=sl,
                        node_id=self._next_id()
                    )
                    imports.append(imp)
                    import_by_symbol[binding] = imp

            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    binding = alias.asname or alias.name

                    imp = ImportInfo(
                        module=module,
                        name=binding,
                        start_line=sl,
                        node_id=self._next_id()
                    )
                    imports.append(imp)
                    import_by_symbol[binding] = imp

            # ------- VARIABLES -------
            if isinstance(node, ast.Assign):
                current = function_stack[-1] if function_stack else None

                for t in node.targets:
                    if isinstance(t, ast.Name):
                        key = (t.id, current, module_name)

                        # Only one VariableInfo per (name, scope, module)
                        if key in variables_by_key:
                            continue

                        v = VariableInfo(
                            name=t.id,
                            module=module_name,
                            defined_in_function=current,
                            start_line=sl,
                            node_id=node_id,
                        )
                        variables.append(v)
                        variables_by_key[key] = v

            # ------- CONTROL FLOW (for completeness) -------
            cf_kind: Optional[str] = None
            if isinstance(node, ast.If):
                cf_kind = "if"
            elif isinstance(node, ast.For):
                cf_kind = "for"
            elif isinstance(node, ast.While):
                cf_kind = "while"
            elif isinstance(node, ast.Try):
                cf_kind = "try"
            elif isinstance(node, ast.With):
                cf_kind = "with"

            if cf_kind is not None:
                current_fn = function_stack[-1] if function_stack else None
                control_flows.append(
                    ControlFlowInfo(
                        kind=cf_kind,
                        start_line=sl,
                        end_line=el,
                        node_id=node_id,
                        parent_function=current_fn,
                    )
                )

            # ------- CALLS -------
            if isinstance(node, ast.Call) and function_stack:
                callee_name: Optional[str] = None
                if isinstance(node.func, ast.Name):
                    callee_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    callee_name = node.func.attr

                if callee_name:
                    calls.append(
                        CallInfo(
                            caller=function_stack[-1],
                            callee=callee_name,
                            line=sl
                        )
                    )

            # ------- USAGE: Name (Load) -------
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                current = function_stack[-1] if function_stack else None

                # import usage (bound name in this module)
                if node.id in import_by_symbol:
                    imp = import_by_symbol[node.id]
                    import_usages.append(
                        ImportUsageInfo(
                            import_node_id=imp.node_id,
                            user_node_id=node_id,
                            symbol=node.id,
                            in_function=current,
                            line=sl
                        )
                    )

                # variable usage (local or module-level within THIS file)
                key = (node.id, current, module_name)
                v = variables_by_key.get(key)
                if v is None:
                    # try module-level/global in same module
                    key2 = (node.id, None, module_name)
                    v = variables_by_key.get(key2)

                if v:
                    variable_usages.append(
                        VariableUsageInfo(
                            variable_node_id=v.node_id,
                            user_node_id=node_id,
                            name=node.id,
                            in_function=current,
                            line=sl
                        )
                    )

            # ------- RECURSE -------
            for child in ast.iter_child_nodes(node):
                traverse(child, node_id)

            if isinstance(node, ast.FunctionDef):
                function_stack.pop()

            return node_id

        traverse(tree)

        # ---------- UNREACHABLE CODE DETECTION ----------

        unreachable_map: Dict[int, str] = {}

        def mark_unreachable(s: ast.AST, reason: str):
            nid = ast_to_id.get(s)
            if nid is not None:
                unreachable_map[nid] = reason

        def static_bool(test: ast.AST) -> Optional[bool]:
            if isinstance(test, ast.Constant):
                return bool(test.value)
            return None

        def scan(stmts: List[ast.stmt]):
            terminated = False
            for s in stmts:
                if isinstance(s, ast.FunctionDef):
                    scan(s.body)
                    continue

                if terminated:
                    mark_unreachable(s, "after-terminator")
                    continue

                if isinstance(s, ast.If):
                    val = static_bool(s.test)
                    if val is False:
                        for b in s.body:
                            mark_unreachable(b, "if-false-body")
                    elif val is True:
                        for b in s.orelse:
                            mark_unreachable(b, "if-true-else")

                    scan(s.body)
                    scan(s.orelse)
                    continue

                if isinstance(s, (ast.For, ast.AsyncFor)) and isinstance(
                    s.iter, (ast.List, ast.Tuple)
                ) and len(s.iter.elts) == 0:
                    for b in s.body:
                        mark_unreachable(b, "for-empty-iter-body")
                    scan(s.orelse)
                    continue

                if isinstance(s, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                    terminated = True
                    continue

        if isinstance(tree, ast.Module):
            scan(tree.body)

        unreachable = [
            UnreachableInfo(node_id=nid, reason=reason)
            for nid, reason in unreachable_map.items()
        ]

        return FileAnalysis(
            file_path=str(path),
            ast_nodes=list(ast_nodes.values()),
            functions=functions,
            imports=imports,
            variables=variables,
            control_flows=control_flows,
            calls=calls,
            import_usages=import_usages,
            variable_usages=variable_usages,
            unreachable=unreachable
        )


# ---------- CLI ----------

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    r = CodeGraphExtractor().extract_from_file(args.path)

    print(json.dumps({
        "file_path": r.file_path,
        "ast_nodes": [asdict(n) for n in r.ast_nodes],
        "functions": [asdict(n) for n in r.functions],
        "imports": [asdict(n) for n in r.imports],
        "variables": [asdict(n) for n in r.variables],
        "control_flows": [asdict(n) for n in r.control_flows],
        "calls": [asdict(n) for n in r.calls],
        "import_usages": [asdict(n) for n in r.import_usages],
        "variable_usages": [asdict(n) for n in r.variable_usages],
        "unreachable": [asdict(n) for n in r.unreachable],
    }, indent=2 if args.pretty else None))


if __name__ == "__main__":
    main()
