import ts from "typescript";
import { loadModules, location } from "./loader.js";
import { packageId } from "./types.js";
import type { AnalysisInput, CallGraph, GraphEdge, GraphNode } from "./types.js";
export type * from "./types.js";
export { packageId } from "./types.js";

type FunctionNode =
  | ts.FunctionDeclaration
  | ts.FunctionExpression
  | ts.ArrowFunction
  | ts.MethodDeclaration
  | ts.ConstructorDeclaration
  | ts.GetAccessorDeclaration
  | ts.SetAccessorDeclaration;
const isFunction = (node: ts.Node): node is FunctionNode =>
  ts.isFunctionDeclaration(node) ||
  ts.isFunctionExpression(node) ||
  ts.isArrowFunction(node) ||
  ts.isMethodDeclaration(node) ||
  ts.isConstructorDeclaration(node) ||
  ts.isGetAccessorDeclaration(node) ||
  ts.isSetAccessorDeclaration(node);

/** Build a syntactic, conservative call graph. This does not classify vulnerability reachability. */
export async function analyzeProject(input: AnalysisInput): Promise<CallGraph> {
  const { root, modules, entries, diagnostics } = await loadModules(input);
  const options: ts.CompilerOptions = {
    allowJs: true,
    checkJs: true,
    noLib: true,
    noResolve: false,
    types: [],
    moduleDetection: ts.ModuleDetectionKind.Force,
    target: ts.ScriptTarget.Latest,
    module: ts.ModuleKind.NodeNext,
    moduleResolution: ts.ModuleResolutionKind.NodeNext,
    jsx: ts.JsxEmit.Preserve,
  };
  const host = ts.createCompilerHost(options);
  host.getSourceFile = (file) => modules.get(file)?.source;
  host.fileExists = (file) => modules.has(file);
  host.readFile = (file) => modules.get(file)?.source.text;
  host.writeFile = () => {};
  host.resolveModuleNames = (names, containingFile) =>
    names.map((name) => {
      const file = modules.get(containingFile)?.imports.get(name);
      return file ? { resolvedFileName: file, isExternalLibraryImport: false } : undefined;
    });
  const program = ts.createProgram([...modules.keys()], options, host);
  const checker = program.getTypeChecker();
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const nodeIds = new Map<ts.Node, string>();
  const moduleIds = new Map<string, string>();
  const edgeKeys = new Set<string>();

  const addDiagnostic = (node: ts.Node, callerId: string, code: string, message: string) => {
    diagnostics.push({
      status: "undetermined",
      code,
      message,
      location: location(root, node),
      callerId,
    });
  };
  const addEdge = (from: string, to: string, kind: GraphEdge["kind"], node: ts.Node) => {
    const loc = location(root, node);
    const key = `${from}|${to}|${kind}|${loc.file}:${loc.line}:${loc.column}`;
    if (!edgeKeys.has(key)) {
      edgeKeys.add(key);
      edges.push({ from, to, kind, location: loc });
    }
  };

  for (const module of modules.values()) {
    const loc = location(root, module.source);
    const id = `${loc.file}#module`;
    moduleIds.set(module.file, id);
    nodes.push({
      id,
      name: "<module>",
      kind: "module",
      location: loc,
      packageId: module.pkg ? packageId(module.pkg) : null,
    });
    function collect(node: ts.Node) {
      if (isFunction(node) && node.body) {
        const loc = location(root, node);
        const id = `${loc.file}#function:${node.getStart()}`;
        nodeIds.set(node, id);
        const name =
          node.name?.getText() ??
          (ts.isVariableDeclaration(node.parent)
            ? node.parent.name.getText()
            : ts.isPropertyAssignment(node.parent)
              ? node.parent.name.getText()
              : ts.isConstructorDeclaration(node)
                ? "constructor"
                : "<anonymous>");
        nodes.push({
          id,
          name,
          kind: "function",
          location: loc,
          packageId: module.pkg ? packageId(module.pkg) : null,
        });
      }
      ts.forEachChild(node, collect);
    }
    collect(module.source);
    for (const diagnostic of program.getSyntacticDiagnostics(module.source)) {
      const point = module.source.getLineAndCharacterOfPosition(diagnostic.start ?? 0);
      diagnostics.push({
        status: "undetermined",
        code: "parse-error",
        message: ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n"),
        location: { file: loc.file, line: point.line + 1, column: point.character + 1 },
      });
    }
  }

  function importedFile(expression: ts.Expression): string | undefined {
    if (
      !ts.isCallExpression(expression) ||
      !ts.isIdentifier(expression.expression) ||
      expression.expression.text !== "require" ||
      checker.getSymbolAtLocation(expression.expression)?.declarations?.length
    )
      return undefined;
    const argument = expression.arguments[0];
    return argument && ts.isStringLiteralLike(argument)
      ? modules.get(expression.getSourceFile().fileName)?.imports.get(argument.text)
      : undefined;
  }

  function exportedTarget(file: string, name: string, seen: Set<ts.Node>): string | undefined {
    const source = modules.get(file)?.source;
    if (!source) return undefined;
    const moduleSymbol = checker.getSymbolAtLocation(source);
    const symbol =
      moduleSymbol && checker.getExportsOfModule(moduleSymbol).find((item) => item.name === name);
    if (symbol) {
      const result = resolveSymbol(symbol, seen);
      if (result) return result;
    }
    // TypeScript does not always connect CommonJS imports in JS without a full install.
    const candidates: ts.Expression[] = [];
    for (const statement of source.statements) {
      if (
        !ts.isExpressionStatement(statement) ||
        !ts.isBinaryExpression(statement.expression) ||
        statement.expression.operatorToken.kind !== ts.SyntaxKind.EqualsToken
      )
        continue;
      const { left, right } = statement.expression;
      const lhs = left.getText(source).replace(/\s/g, "");
      if (
        lhs === `exports.${name}` ||
        lhs === `module.exports.${name}` ||
        (name === "default" && lhs === "module.exports")
      )
        candidates.push(right);
      if (lhs === "module.exports" && ts.isObjectLiteralExpression(right)) {
        for (const prop of right.properties) {
          if (prop.name?.getText(source).replace(/^['"]|['"]$/g, "") !== name) continue;
          if (ts.isPropertyAssignment(prop)) candidates.push(prop.initializer);
          if (ts.isShorthandPropertyAssignment(prop)) candidates.push(prop.name);
          if (ts.isMethodDeclaration(prop)) return nodeIds.get(prop);
        }
      }
    }
    if (candidates.length === 1) return resolveExpression(candidates[0]!, seen);
    return undefined;
  }

  function resolveSymbol(original: ts.Symbol, seen: Set<ts.Node>): string | undefined {
    const symbol =
      original.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(original) : original;
    const results = new Set<string>();
    for (const declaration of symbol.declarations ?? []) {
      if (seen.has(declaration)) continue;
      const next = new Set(seen).add(declaration);
      const direct = nodeIds.get(declaration);
      if (direct) results.add(direct);
      else if (
        (ts.isVariableDeclaration(declaration) || ts.isPropertyAssignment(declaration)) &&
        declaration.initializer
      ) {
        // Reassignable bindings need flow analysis; never assume their initializer is the call target.
        if (
          ts.isVariableDeclaration(declaration) &&
          !(
            ts.isVariableDeclarationList(declaration.parent) &&
            declaration.parent.flags & ts.NodeFlags.Const
          )
        )
          continue;
        const result = resolveExpression(declaration.initializer, next);
        if (result) results.add(result);
      } else if (
        ts.isBindingElement(declaration) &&
        ts.isVariableDeclaration(declaration.parent.parent)
      ) {
        const variable = declaration.parent.parent;
        if (
          !(
            ts.isVariableDeclarationList(variable.parent) &&
            variable.parent.flags & ts.NodeFlags.Const
          )
        )
          continue;
        const file = variable.initializer && importedFile(variable.initializer);
        if (file) {
          const result = exportedTarget(
            file,
            (declaration.propertyName ?? declaration.name).getText(),
            next,
          );
          if (result) results.add(result);
        }
      } else if (ts.isShorthandPropertyAssignment(declaration)) {
        const value = checker.getShorthandAssignmentValueSymbol(declaration);
        const result = value && resolveSymbol(value, next);
        if (result) results.add(result);
      }
    }
    return results.size === 1 ? [...results][0] : undefined;
  }

  function requireNamespace(expression: ts.Expression): string | undefined {
    const direct = importedFile(expression);
    if (direct) return direct;
    if (!ts.isIdentifier(expression)) return undefined;
    const symbol = checker.getSymbolAtLocation(expression);
    for (const declaration of symbol?.declarations ?? []) {
      if (
        ts.isVariableDeclaration(declaration) &&
        declaration.initializer &&
        ts.isVariableDeclarationList(declaration.parent) &&
        declaration.parent.flags & ts.NodeFlags.Const
      )
        return importedFile(declaration.initializer);
    }
    return undefined;
  }

  function resolveExpression(
    expression: ts.Expression,
    seen = new Set<ts.Node>(),
  ): string | undefined {
    if (seen.has(expression)) return undefined;
    const next = new Set(seen).add(expression);
    const direct = nodeIds.get(expression);
    if (direct) return direct;
    if (
      ts.isParenthesizedExpression(expression) ||
      ts.isAsExpression(expression) ||
      ts.isNonNullExpression(expression) ||
      ts.isTypeAssertionExpression(expression) ||
      ts.isSatisfiesExpression(expression)
    )
      return resolveExpression(expression.expression, next);
    const file = importedFile(expression);
    if (file) return exportedTarget(file, "default", next);
    if (ts.isPropertyAccessExpression(expression)) {
      const namespace = requireNamespace(expression.expression);
      if (namespace) return exportedTarget(namespace, expression.name.text, next);
    }
    if (ts.isIdentifier(expression) || ts.isPropertyAccessExpression(expression)) {
      const symbol = checker.getSymbolAtLocation(
        ts.isPropertyAccessExpression(expression) ? expression.name : expression,
      );
      if (symbol) return resolveSymbol(symbol, next);
    }
    return undefined;
  }

  for (const module of modules.values()) {
    function walk(node: ts.Node, caller: string) {
      const owner = nodeIds.get(node) ?? caller;
      if (
        (ts.isImportDeclaration(node) && !node.importClause?.isTypeOnly) ||
        (ts.isExportDeclaration(node) && !node.isTypeOnly)
      ) {
        const specifier = node.moduleSpecifier;
        const file =
          specifier && ts.isStringLiteralLike(specifier)
            ? module.imports.get(specifier.text)
            : undefined;
        if (file) addEdge(owner, moduleIds.get(file)!, "module-load", node);
      }
      if (
        ts.isImportEqualsDeclaration(node) &&
        !node.isTypeOnly &&
        ts.isExternalModuleReference(node.moduleReference)
      ) {
        const expression = node.moduleReference.expression;
        const file =
          expression && ts.isStringLiteralLike(expression)
            ? module.imports.get(expression.text)
            : undefined;
        if (file) addEdge(owner, moduleIds.get(file)!, "module-load", node);
      }
      if (ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node))
        addDiagnostic(node, owner, "accessor-flow", "Implicit accessor invocation is not modeled.");
      if (ts.isPropertyDeclaration(node) && node.initializer)
        addDiagnostic(
          node,
          owner,
          "class-initializer-flow",
          "Class field initializer execution timing is not modeled.",
        );
      if (ts.isDecorator(node))
        addDiagnostic(
          node,
          owner,
          "decorator-flow",
          "Implicit decorator invocation is not modeled.",
        );
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
        node.operatorToken.kind <= ts.SyntaxKind.LastAssignment
      )
        addDiagnostic(
          node,
          owner,
          "mutation-flow",
          "Assignment may change call targets; graph edges represent syntactic candidates, not flow-sensitive targets.",
        );
      if (ts.isCallExpression(node) || ts.isNewExpression(node)) {
        const expression = node.expression;
        const isRequire =
          ts.isIdentifier(expression) &&
          expression.text === "require" &&
          !checker.getSymbolAtLocation(expression)?.declarations?.length;
        const isImport = expression.kind === ts.SyntaxKind.ImportKeyword;
        if (isRequire || isImport) {
          const argument = node.arguments?.[0];
          const file =
            argument && ts.isStringLiteralLike(argument)
              ? module.imports.get(argument.text)
              : undefined;
          if (file) addEdge(owner, moduleIds.get(file)!, "module-load", node);
          if (isImport)
            addDiagnostic(
              node,
              owner,
              "dynamic-import-value",
              "Module loading is recorded; Promise-based import value flow is not modeled.",
            );
        } else if (
          ts.isIdentifier(expression) &&
          expression.text === "eval" &&
          !checker.getSymbolAtLocation(expression)?.declarations?.length
        ) {
          addDiagnostic(
            node,
            owner,
            "dynamic-eval",
            "eval can execute code unavailable to static analysis.",
          );
        } else {
          let target = resolveExpression(expression);
          if (ts.isNewExpression(node)) {
            const declaration = checker.getResolvedSignature(node)?.declaration;
            target =
              declaration && ts.isConstructorDeclaration(declaration)
                ? nodeIds.get(declaration)
                : undefined;
          }
          if (target) {
            addEdge(owner, target, ts.isNewExpression(node) ? "construct" : "call", node);
            if (ts.isPropertyAccessExpression(expression))
              addDiagnostic(
                node,
                owner,
                "member-dispatch",
                "Declared member target recorded; runtime overrides and property mutation are not modeled.",
              );
          } else
            addDiagnostic(
              node,
              owner,
              "unresolved-call",
              `Cannot determine call target: ${expression.getText()}`,
            );
          for (const argument of node.arguments ?? []) {
            if (resolveExpression(argument))
              addDiagnostic(
                argument,
                owner,
                "callback-flow",
                "Function passed as an argument; callback invocation flow is not modeled.",
              );
          }
        }
      }
      if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node))
        addDiagnostic(
          node,
          owner,
          "jsx-dispatch",
          "Framework component invocation is not modeled.",
        );
      if (ts.isTaggedTemplateExpression(node))
        addDiagnostic(node, owner, "tagged-template", "Tagged-template invocation is not modeled.");
      ts.forEachChild(node, (child) => walk(child, owner));
    }
    walk(module.source, moduleIds.get(module.file)!);
  }
  return {
    nodes,
    edges,
    entryPointIds: entries.map((file) => moduleIds.get(file)!),
    diagnostics,
    packages: input.manifest.packages.map((pkg) => ({ ...pkg, id: packageId(pkg) })),
  };
}
