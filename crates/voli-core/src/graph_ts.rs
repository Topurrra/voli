//! Tree-sitter extraction engine for `voli graph`.
//!
//! One generic core, per-language query tables. Every language maps onto the
//! same [`TsFile`] model (typed defs, imports, calls), so adding a language
//! is new queries — never new engine code.
//!
//! Conventions (`@` captures):
//! - `@d.<kind>` the definition node; kind ∈ class, struct, enum, trait, fn,
//!   method, mod, const, type. `@n` inside it is the name node, `@x` an
//!   optional detail node (Go receiver, Go type body).
//! - `@d.impl` + `@n` is a *parent marker* (Rust `impl`, no symbol of its own).
//! - `@i` an import/include/use node (whole statement; text normalized later).
//! - `@c` a call node, `@cn` the callee name leaf, `@cq` an optional
//!   qualifier leaf (`Type::`, `obj.`, `pkg.` …).
//!
//! Queries are stored **one pattern per string** and compiled independently:
//! a pattern that doesn't fit a grammar downgrade degrades that one concept,
//! never the whole language. Method parenting is range-based (nearest
//! enclosing type-like def), never tied to grammar-version field layouts.

use std::cell::RefCell;
use std::collections::HashMap;

use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor};

use super::graph::NodeKind;

// Compiled parsers/queries cached per thread: a full rebuild compiles each
// pattern once, not once per file (was ~80% of build time).
thread_local! {
    static PARSERS: RefCell<HashMap<TsLang, Parser>> = RefCell::new(HashMap::new());
    static QUERIES: RefCell<HashMap<(TsLang, u8, usize), Option<Query>>> =
        RefCell::new(HashMap::new());
}

/// Run `f` with a cached compiled pattern (`table`: 0 = defs, 1 = calls,
/// 2 = imports). Uncompilable patterns are cached as misses.
fn with_query<T>(lang: TsLang, language: &Language, table: u8, idx: usize, src: &str, f: impl FnOnce(&Query) -> T) -> Option<T> {
    QUERIES.with(|qc| {
        let mut qc = qc.borrow_mut();
        let entry = qc.entry((lang, table, idx)).or_insert_with(|| Query::new(language, src).ok());
        entry.as_ref().map(f)
    })
}

// ---------------------------------------------------------------------------
// Version-free model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TsItem {
    pub kind: NodeKind,
    pub name: String,
    pub qualified: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub line: u32,
    pub parent: Option<String>,
    pub bases: Vec<String>,
    pub is_test: bool,
}

/// `impl Trait for Type` (Rust) — resolved to node ids by the caller.
#[derive(Debug, Clone)]
pub struct TsImpl {
    pub ty: String,
    pub tr: String,
}

#[derive(Debug, Clone)]
pub struct TsCall {
    pub start_byte: usize,
    pub qualifier: Option<String>,
    pub name: String,
}

#[derive(Debug, Default)]
pub struct TsFile {
    pub items: Vec<TsItem>,
    pub calls: Vec<TsCall>,
    pub imports: Vec<String>,
    pub impls: Vec<TsImpl>,
    /// True when the tree is mostly ERROR nodes — caller should fall back.
    pub broken: bool,
}

// ---------------------------------------------------------------------------
// Languages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TsLang {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Tsx,
    Go,
    Java,
    C,
    Cpp,
    CSharp,
    Ruby,
    Bash,
    Php,
    Css,
    Yaml,
    PowerShell,
    Julia,
    Groovy,
    Pascal,
    Verilog,
    Zig,
    Fortran,
    Ocaml,
    ObjC,
    Xml,
    Scala,
    Json,
    Html,
}

/// Extension → language. `None` means "not a tree-sitter language" (caller
/// tries manifests, markdown, sql, then the regex fallback, then file node).
pub fn lang_for_ext(ext: &str) -> Option<TsLang> {
    Some(match ext {
        "rs" => TsLang::Rust,
        "py" | "pyi" => TsLang::Python,
        "js" | "jsx" | "mjs" | "cjs" => TsLang::JavaScript,
        "ts" | "mts" | "cts" => TsLang::TypeScript,
        "tsx" => TsLang::Tsx,
        "go" => TsLang::Go,
        "java" => TsLang::Java,
        "c" | "h" => TsLang::C,
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "cu" | "cuh" | "metal" => TsLang::Cpp,
        "cs" => TsLang::CSharp,
        "rb" => TsLang::Ruby,
        "sh" | "bash" => TsLang::Bash,
        "php" => TsLang::Php,
        "css" => TsLang::Css,
        "yaml" | "yml" => TsLang::Yaml,
        "ps1" | "psm1" | "psd1" => TsLang::PowerShell,
        "jl" => TsLang::Julia,
        "groovy" | "gradle" => TsLang::Groovy,
        "pas" | "pp" | "dpr" | "dpk" | "lpr" | "inc" | "dfm" | "lfm" | "lpk" => TsLang::Pascal,
        "v" | "sv" | "svh" => TsLang::Verilog,
        "zig" => TsLang::Zig,
        "f" | "f90" | "f95" | "f03" | "f08" | "for" => TsLang::Fortran,
        "ml" | "mli" => TsLang::Ocaml,
        "m" | "mm" => TsLang::ObjC,
        "xml" | "csproj" | "fsproj" | "vbproj" | "props" | "targets" | "xaml" => TsLang::Xml,
        "scala" | "sbt" => TsLang::Scala,
        "json" => TsLang::Json,
        "html" | "htm" => TsLang::Html,
        _ => return None,
    })
}

fn language(lang: TsLang) -> Language {
    match lang {
        TsLang::Rust => tree_sitter_rust::LANGUAGE.into(),
        TsLang::Python => tree_sitter_python::LANGUAGE.into(),
        TsLang::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        TsLang::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        TsLang::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        TsLang::Go => tree_sitter_go::LANGUAGE.into(),
        TsLang::Java => tree_sitter_java::LANGUAGE.into(),
        TsLang::C => tree_sitter_c::LANGUAGE.into(),
        TsLang::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        TsLang::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        TsLang::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        TsLang::Bash => tree_sitter_bash::LANGUAGE.into(),
        TsLang::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        TsLang::Css => tree_sitter_css::LANGUAGE.into(),
        TsLang::Yaml => tree_sitter_yaml::LANGUAGE.into(),
        TsLang::PowerShell => tree_sitter_powershell::language(),
        TsLang::Julia => tree_sitter_julia::LANGUAGE.into(),
        TsLang::Groovy => tree_sitter_groovy::LANGUAGE.into(),
        TsLang::Pascal => tree_sitter_pascal::LANGUAGE.into(),
        TsLang::Verilog => tree_sitter_verilog::LANGUAGE.into(),
        TsLang::Zig => tree_sitter_zig::LANGUAGE.into(),
        TsLang::Fortran => tree_sitter_fortran::LANGUAGE.into(),
        TsLang::Ocaml => tree_sitter_ocaml::LANGUAGE_OCAML.into(),
        TsLang::ObjC => tree_sitter_objc::LANGUAGE.into(),
        TsLang::Xml => tree_sitter_xml::LANGUAGE_XML.into(),
        TsLang::Scala => tree_sitter_scala::LANGUAGE.into(),
        TsLang::Json => tree_sitter_json::LANGUAGE.into(),
        TsLang::Html => tree_sitter_html::LANGUAGE.into(),
    }
}

// ---------------------------------------------------------------------------
// Query tables (one pattern per string; independent compilation)
// ---------------------------------------------------------------------------

struct LangQueries {
    defs: &'static [&'static str],
    /// Base-type / impl-trait patterns (same match carries @d+@n+@b).
    more_defs: &'static [&'static str],
    calls: &'static [&'static str],
    imports: &'static [&'static str],
}

const NO_MORE: &[&str] = &[];
const NO_CALLS: &[&str] = &[];
const NO_IMPORTS: &[&str] = &[];

// -- Rust -------------------------------------------------------------------
const RUST_DEFS: &[&str] = &[
    "(struct_item name: (type_identifier) @n) @d.struct",
    "(enum_item name: (type_identifier) @n) @d.enum",
    "(trait_item name: (type_identifier) @n) @d.trait",
    "(function_item name: (identifier) @n) @d.fn",
    "(mod_item name: (identifier) @n) @d.mod",
    "(const_item name: (identifier) @n) @d.const",
    "(static_item name: (identifier) @n) @d.const",
    "(impl_item type: (type_identifier) @n) @d.impl",
];
const RUST_CALLS: &[&str] = &[
    "(call_expression function: (identifier) @cn) @c",
    "(call_expression function: (scoped_identifier path: (_) @cq name: (identifier) @cn)) @c",
    "(call_expression function: (field_expression field: (field_identifier) @cn)) @c",
];
const RUST_IMPORTS: &[&str] = &["(use_declaration argument: (_) @i) @imp"];

// -- Python -----------------------------------------------------------------
const PYTHON_DEFS: &[&str] = &[
    "(class_definition name: (identifier) @n) @d.class",
    "(function_definition name: (identifier) @n) @d.fn",
];
const PYTHON_CALLS: &[&str] = &[
    "(call function: (identifier) @cn) @c",
    "(call function: (attribute object: (_) @cq attribute: (identifier) @cn)) @c",
];
const PYTHON_IMPORTS: &[&str] = &[
    "(import_statement name: (dotted_name) @i) @imp",
    "(import_statement (aliased_import name: (dotted_name) @i)) @imp",
    "(import_from_statement module_name: (dotted_name) @i) @imp",
];

// -- JavaScript --------------------------------------------------------------
const JS_DEFS: &[&str] = &[
    "(class_declaration name: (identifier) @n) @d.class",
    "(function_declaration name: (identifier) @n) @d.fn",
    "(generator_function_declaration name: (identifier) @n) @d.fn",
    "(method_definition name: (property_identifier) @n) @d.method",
];
const JS_CALLS: &[&str] = &[
    "(call_expression function: (identifier) @cn) @c",
    "(call_expression function: (member_expression object: (_) @cq property: (property_identifier) @cn)) @c",
    "(new_expression constructor: (identifier) @cn) @c",
];
const JS_IMPORTS: &[&str] = &[
    "(import_statement source: (string) @i) @imp",
    "(export_statement source: (string) @i) @imp",
    r#"(call_expression function: (identifier) @f arguments: (arguments (string) @i) (#eq? @f "require")) @imp"#,
];

// -- TypeScript (JS + interfaces / aliases / enums) ---------------------------
const TS_DEFS: &[&str] = &[
    "(class_declaration name: (type_identifier) @n) @d.class",
    "(function_declaration name: (identifier) @n) @d.fn",
    "(generator_function_declaration name: (identifier) @n) @d.fn",
    "(method_definition name: (property_identifier) @n) @d.method",
    "(interface_declaration name: (type_identifier) @n) @d.trait",
    "(type_alias_declaration name: (type_identifier) @n) @d.struct",
    "(enum_declaration name: (identifier) @n) @d.enum",
];

// -- Go ----------------------------------------------------------------------
const GO_DEFS: &[&str] = &[
    "(type_spec name: (type_identifier) @n type: (_) @x) @d.type",
    "(function_declaration name: (identifier) @n) @d.fn",
    "(method_declaration receiver: (parameter_list) @x name: (field_identifier) @n) @d.method",
];
const GO_CALLS: &[&str] = &[
    "(call_expression function: (identifier) @cn) @c",
    "(call_expression function: (selector_expression operand: (_) @cq field: (field_identifier) @cn)) @c",
];
const GO_IMPORTS: &[&str] = &["(import_spec path: (_) @i) @imp"];

// -- Java --------------------------------------------------------------------
const JAVA_DEFS: &[&str] = &[
    "(class_declaration name: (identifier) @n) @d.class",
    "(interface_declaration name: (identifier) @n) @d.trait",
    "(enum_declaration name: (identifier) @n) @d.enum",
    "(method_declaration name: (identifier) @n) @d.method",
    "(constructor_declaration name: (identifier) @n) @d.method",
];
const JAVA_CALLS: &[&str] = &[
    "(method_invocation name: (identifier) @cn) @c",
    "(method_invocation object: (_) @cq name: (identifier) @cn) @c",
    "(object_creation_expression type: (type_identifier) @cn) @c",
];
const JAVA_IMPORTS: &[&str] = &["(import_declaration (_) @i) @imp"];

// -- C ------------------------------------------------------------------------
const C_DEFS: &[&str] = &[
    "(struct_specifier name: (type_identifier) @n) @d.struct",
    "(enum_specifier name: (type_identifier) @n) @d.enum",
    "(function_definition declarator: (function_declarator declarator: (identifier) @n)) @d.fn",
];
const C_CALLS: &[&str] = &[
    "(call_expression function: (identifier) @cn) @c",
    "(call_expression function: (field_expression field: (field_identifier) @cn)) @c",
];
const C_IMPORTS: &[&str] = &["(preproc_include path: (_) @i) @imp"];

// -- C++ (C + classes / namespaces) --------------------------------------------
const CPP_DEFS: &[&str] = &[
    "(class_specifier name: (type_identifier) @n) @d.class",
    "(struct_specifier name: (type_identifier) @n) @d.struct",
    "(enum_specifier name: (type_identifier) @n) @d.enum",
    "(function_definition declarator: (function_declarator declarator: (identifier) @n)) @d.fn",
    "(namespace_definition name: (identifier) @n) @d.mod",
];

// -- C# -------------------------------------------------------------------------
const CSHARP_DEFS: &[&str] = &[
    "(class_declaration name: (identifier) @n) @d.class",
    "(interface_declaration name: (identifier) @n) @d.trait",
    "(enum_declaration name: (identifier) @n) @d.enum",
    "(method_declaration name: (identifier) @n) @d.method",
    "(constructor_declaration name: (identifier) @n) @d.method",
    "(namespace_declaration name: (identifier) @n) @d.mod",
];
const CSHARP_CALLS: &[&str] = &[
    "(invocation_expression function: (identifier) @cn) @c",
    "(invocation_expression function: (member_access_expression expression: (_) @cq name: (identifier) @cn)) @c",
    "(object_creation_expression type: (identifier) @cn) @c",
];
const CSHARP_IMPORTS: &[&str] = &["(using_directive (_) @i) @imp"];

// -- Ruby -----------------------------------------------------------------------
const RUBY_DEFS: &[&str] = &[
    "(class name: (constant) @n) @d.class",
    "(module name: (constant) @n) @d.mod",
    "(method name: (identifier) @n) @d.fn",
    "(singleton_method name: (identifier) @n) @d.method",
];
const RUBY_CALLS: &[&str] = &[
    "(call method: (identifier) @cn) @c",
    "(call receiver: (_) @cq method: (identifier) @cn) @c",
];
const RUBY_IMPORTS: &[&str] = &[
    r#"(call method: (identifier) @m arguments: (argument_list (string) @i) (#eq? @m "require")) @imp"#,
    r#"(call method: (identifier) @m arguments: (argument_list (string) @i) (#eq? @m "require_relative")) @imp"#,
    r#"(call method: (identifier) @m arguments: (argument_list (string) @i) (#eq? @m "load")) @imp"#,
];

// -- Bash -------------------------------------------------------------------------
const BASH_DEFS: &[&str] = &["(function_definition name: (word) @n) @d.fn"];
const BASH_CALLS: &[&str] = &["(command name: (command_name (word) @cn)) @c"];
const BASH_IMPORTS: &[&str] = &[
    r#"(command name: (command_name (word) @s) argument: (word) @i (#eq? @s "source")) @imp"#,
    r#"(command name: (command_name (word) @s) argument: (word) @i (#eq? @s ".")) @imp"#,
];

// -- PHP ----------------------------------------------------------------------------
const PHP_DEFS: &[&str] = &[
    "(class_declaration name: (name) @n) @d.class",
    "(interface_declaration name: (name) @n) @d.trait",
    "(enum_declaration name: (name) @n) @d.enum",
    "(function_definition name: (name) @n) @d.fn",
    "(method_declaration name: (name) @n) @d.method",
];
const PHP_CALLS: &[&str] = &[
    "(function_call_expression function: (name) @cn) @c",
    "(scoped_call_expression scope: (name) @cq name: (name) @cn) @c",
    "(member_call_expression object: (_) @cq name: (name) @cn) @c",
];
const PHP_IMPORTS: &[&str] = &["(namespace_use_declaration (_) @i) @imp"];

// -- Scala ---------------------------------------------------------------------
const SCALA_DEFS: &[&str] = &[
    "(class_definition name: (identifier) @n) @d.class",
    "(object_definition name: (identifier) @n) @d.mod",
    "(trait_definition name: (identifier) @n) @d.trait",
    "(function_definition name: (identifier) @n) @d.fn",
    "(class_definition name: (identifier) @n extend: (extends_clause type: (type_identifier) @b)) @d.class",
];
const SCALA_CALLS: &[&str] = &[
    "(call_expression function: (identifier) @cn) @c",
    "(call_expression function: (field_expression value: (_) @cq field: (identifier) @cn)) @c",
];
const SCALA_IMPORTS: &[&str] = &["(import_declaration (identifier) @i) @imp"];

// -- Zig -------------------------------------------------------------------------
const ZIG_DEFS: &[&str] = &[
    "(variable_declaration (identifier) @n (struct_declaration)) @d.struct",
    "(function_declaration name: (identifier) @n) @d.fn",
];
const ZIG_IMPORTS: &[&str] = &[
    r#"(variable_declaration (identifier) (builtin_function (builtin_identifier) @_b (arguments (string) @i)) (#eq? @_b "@import")) @imp"#,
];

// -- Julia -------------------------------------------------------------------------
const JULIA_DEFS: &[&str] = &[
    "(module_definition name: (identifier) @n) @d.mod",
    "(struct_definition (type_head (identifier) @n)) @d.struct",
    "(function_definition (signature (call_expression (identifier) @n))) @d.fn",
];
const JULIA_CALLS: &[&str] = &["(call_expression (identifier) @cn) @c"];
const JULIA_IMPORTS: &[&str] = &[
    "(using_statement (identifier) @i) @imp",
    "(import_statement (identifier) @i) @imp",
];

// -- Groovy --------------------------------------------------------------------------
const GROOVY_DEFS: &[&str] = &[
    "(class_declaration name: (identifier) @n) @d.class",
    "(interface_declaration name: (identifier) @n) @d.trait",
    "(method_declaration name: (identifier) @n) @d.method",
];
const GROOVY_CALLS: &[&str] = &[
    "(method_invocation name: (identifier) @cn) @c",
    "(method_invocation object: (identifier) @cq name: (identifier) @cn) @c",
];
const GROOVY_IMPORTS: &[&str] = &["(import_declaration (_) @i) @imp"];

// -- Pascal ----------------------------------------------------------------------------
const PASCAL_DEFS: &[&str] = &[
    "(declType name: (identifier) @n) @d.struct",
    "(declProc name: (identifier) @n) @d.method",
    "(declProc name: (genericDot lhs: (identifier) @qn rhs: (identifier) @n)) @d.method",
    "(unit (moduleName (identifier) @n)) @d.mod",
];
const PASCAL_CALLS: &[&str] = &["(call (identifier) @cn) @c"];
const PASCAL_IMPORTS: &[&str] = &[
    "(usesClause (identifier) @i) @imp",
    "(uses (identifier) @i) @imp",
];

// -- Verilog -----------------------------------------------------------------------------
const VERILOG_DEFS: &[&str] = &[
    "(module_declaration (module_header (module_keyword) . (simple_identifier) @n)) @d.mod",
];
const VERILOG_CALLS: &[&str] = &["(module_instantiation (simple_identifier) @cn) @c"];

// -- Fortran -------------------------------------------------------------------------------
const FORTRAN_DEFS: &[&str] = &[
    "(module (module_statement (name) @n)) @d.mod",
    "(subroutine (subroutine_statement name: (name) @n)) @d.fn",
    "(function_statement name: (name) @n) @d.fn",
    "(function (function_statement name: (name) @n)) @d.fn",
];
const FORTRAN_CALLS: &[&str] = &["(subroutine_call subroutine: (identifier) @cn) @c"];

// -- Objective-C (C + interfaces) ---------------------------------------------------------------
const OBJC_DEFS: &[&str] = &[
    "(class_interface (identifier) @n) @d.class",
    "(class_interface (identifier) @n superclass: (identifier) @b) @d.class",
    "(class_implementation (identifier) @n) @d.impl",
    "(method_declaration (identifier) @n) @d.method",
    "(struct_specifier name: (type_identifier) @n) @d.struct",
    "(enum_specifier name: (type_identifier) @n) @d.enum",
    "(function_definition declarator: (function_declarator declarator: (identifier) @n)) @d.fn",
];
const OBJC_CALLS: &[&str] = &[
    "(call_expression function: (identifier) @cn) @c",
    "(message_expression receiver: (_) @cq selector: (identifier) @cn) @c",
];

// -- OCaml ----------------------------------------------------------------------------------
const OCAML_DEFS: &[&str] = &[
    "(module_binding (module_name) @n) @d.mod",
    "(value_definition (let_binding pattern: (value_name) @n)) @d.fn",
];
const OCAML_CALLS: &[&str] = &[
    "(application_expression function: (value_path (value_name) @cn)) @c",
];
const OCAML_IMPORTS: &[&str] = &["(open_module (module_name) @i) @imp"];

// -- PowerShell -------------------------------------------------------------------------------------
const POWERSHELL_DEFS: &[&str] = &[
    "(function_statement (function_name) @n) @d.fn",
    "(function_statement name: (function_name) @n) @d.fn",
];
const POWERSHELL_CALLS: &[&str] = &["(command command_name: (command_name) @cn) @c"];
const POWERSHELL_IMPORTS: &[&str] = &[
    "(command (command_invokation_operator) (command_elements) @i) @imp",
    "(using_statement (_) @i) @imp",
];

// -- CSS (selectors as style nodes) ----------------------------------------------------------------------
const CSS_DEFS: &[&str] = &[
    "(rule_set selectors: (selectors) @n) @d.style",
    "(rule_set (selectors) @n) @d.style",
];

// -- XML (distinct element names) ------------------------------------------------------------------
const XML_DEFS: &[&str] = &[
    "(element (STag (Name) @n)) @d.tag",
    "(element (EmptyElemTag (Name) @n)) @d.tag",
];

// -- JSON (object keys as const nodes; merged per file) ----------------------------------------------
const JSON_DEFS: &[&str] = &["(pair key: (string (string_content) @n)) @d.const"];

// -- YAML (mapping keys as const nodes; merged per file) -----------------------------------------------
const YAML_DEFS: &[&str] = &[
    "(block_mapping_pair key: (_) @n) @d.const",
    "(flow_pair key: (_) @n) @d.const",
];

// -- Base-type patterns appended to established languages -----------------------------------------------
// (Same match carries @d + @n + @b, so bases attach to the right symbol.)
const TS_BASES: &[&str] = &[
    "(class_declaration name: (type_identifier) @n (class_heritage (extends_clause (identifier) @b))) @d.class",
    "(class_declaration name: (type_identifier) @n (class_heritage (implements_clause (type_identifier) @b))) @d.class",
];
const PYTHON_BASES: &[&str] = &[
    "(class_definition name: (identifier) @n (argument_list (identifier) @b)) @d.class",
    "(class_definition name: (identifier) @n (argument_list (attribute attribute: (identifier) @b))) @d.class",
];
const JAVA_BASES: &[&str] = &[
    "(class_declaration name: (identifier) @n (superclass (type_identifier) @b)) @d.class",
    "(class_declaration name: (identifier) @n (super_interfaces (type_interface_list (type_identifier) @b))) @d.class",
];
const CPP_BASES: &[&str] = &[
    "(class_specifier name: (type_identifier) @n (base_class_clause (type_identifier) @b)) @d.class",
    "(class_specifier name: (type_identifier) @n (base_class_clause (access_specifier) (type_identifier) @b)) @d.class",
];
const CSHARP_BASES: &[&str] = &[
    "(class_declaration name: (identifier) @n (base_list (identifier) @b)) @d.class",
    "(class_declaration name: (identifier) @n (base_list (qualified_name) @b)) @d.class",
];
const RUBY_BASES: &[&str] = &[
    "(class name: (constant) @n superclass: (superclass (constant) @b)) @d.class",
];
const PHP_BASES: &[&str] = &[
    "(class_declaration name: (name) @n (base_clause (name) @b)) @d.class",
];
const RUST_IMPL: &[&str] = &["(impl_item trait: (type_identifier) @t type: (type_identifier) @y)"];

fn queries(lang: TsLang) -> Option<LangQueries> {
    Some(match lang {
        TsLang::Rust => LangQueries { defs: RUST_DEFS, more_defs: RUST_IMPL, calls: RUST_CALLS, imports: RUST_IMPORTS },
        TsLang::Python => LangQueries { defs: PYTHON_DEFS, more_defs: PYTHON_BASES, calls: PYTHON_CALLS, imports: PYTHON_IMPORTS },
        TsLang::JavaScript => LangQueries { defs: JS_DEFS, more_defs: NO_MORE, calls: JS_CALLS, imports: JS_IMPORTS },
        TsLang::TypeScript | TsLang::Tsx => LangQueries { defs: TS_DEFS, more_defs: TS_BASES, calls: JS_CALLS, imports: JS_IMPORTS },
        TsLang::Go => LangQueries { defs: GO_DEFS, more_defs: NO_MORE, calls: GO_CALLS, imports: GO_IMPORTS },
        TsLang::Java => LangQueries { defs: JAVA_DEFS, more_defs: JAVA_BASES, calls: JAVA_CALLS, imports: JAVA_IMPORTS },
        TsLang::C => LangQueries { defs: C_DEFS, more_defs: NO_MORE, calls: C_CALLS, imports: C_IMPORTS },
        TsLang::Cpp => LangQueries { defs: CPP_DEFS, more_defs: CPP_BASES, calls: C_CALLS, imports: C_IMPORTS },
        TsLang::CSharp => LangQueries { defs: CSHARP_DEFS, more_defs: CSHARP_BASES, calls: CSHARP_CALLS, imports: CSHARP_IMPORTS },
        TsLang::Ruby => LangQueries { defs: RUBY_DEFS, more_defs: RUBY_BASES, calls: RUBY_CALLS, imports: RUBY_IMPORTS },
        TsLang::Bash => LangQueries { defs: BASH_DEFS, more_defs: NO_MORE, calls: BASH_CALLS, imports: BASH_IMPORTS },
        TsLang::Php => LangQueries { defs: PHP_DEFS, more_defs: PHP_BASES, calls: PHP_CALLS, imports: PHP_IMPORTS },
        TsLang::Scala => LangQueries { defs: SCALA_DEFS, more_defs: NO_MORE, calls: SCALA_CALLS, imports: SCALA_IMPORTS },
        TsLang::Zig => LangQueries { defs: ZIG_DEFS, more_defs: NO_MORE, calls: NO_CALLS, imports: ZIG_IMPORTS },
        TsLang::Julia => LangQueries { defs: JULIA_DEFS, more_defs: NO_MORE, calls: JULIA_CALLS, imports: JULIA_IMPORTS },
        TsLang::Groovy => LangQueries { defs: GROOVY_DEFS, more_defs: NO_MORE, calls: GROOVY_CALLS, imports: GROOVY_IMPORTS },
        TsLang::Pascal => LangQueries { defs: PASCAL_DEFS, more_defs: NO_MORE, calls: PASCAL_CALLS, imports: PASCAL_IMPORTS },
        TsLang::Verilog => LangQueries { defs: VERILOG_DEFS, more_defs: NO_MORE, calls: VERILOG_CALLS, imports: NO_IMPORTS },
        TsLang::Fortran => LangQueries { defs: FORTRAN_DEFS, more_defs: NO_MORE, calls: FORTRAN_CALLS, imports: NO_IMPORTS },
        TsLang::ObjC => LangQueries { defs: OBJC_DEFS, more_defs: NO_MORE, calls: OBJC_CALLS, imports: C_IMPORTS },
        TsLang::Ocaml => LangQueries { defs: OCAML_DEFS, more_defs: NO_MORE, calls: OCAML_CALLS, imports: OCAML_IMPORTS },
        TsLang::PowerShell => LangQueries { defs: POWERSHELL_DEFS, more_defs: NO_MORE, calls: POWERSHELL_CALLS, imports: POWERSHELL_IMPORTS },
        TsLang::Css => LangQueries { defs: CSS_DEFS, more_defs: NO_MORE, calls: NO_CALLS, imports: NO_IMPORTS },
        TsLang::Xml => LangQueries { defs: XML_DEFS, more_defs: NO_MORE, calls: NO_CALLS, imports: NO_IMPORTS },
        TsLang::Json => LangQueries { defs: JSON_DEFS, more_defs: NO_MORE, calls: NO_CALLS, imports: NO_IMPORTS },
        TsLang::Yaml => LangQueries { defs: YAML_DEFS, more_defs: NO_MORE, calls: NO_CALLS, imports: NO_IMPORTS },
        // Json / Html / Yaml / Xml: file nodes only (no symbol queries v1).
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

fn text_of(node: Node, text: &str) -> String {
    node.utf8_text(text.as_bytes()).unwrap_or("").to_string()
}

fn kind_of(capture: &str) -> Option<NodeKind> {
    Some(match capture {
        "d.class" => NodeKind::Struct, // classes map to struct (documented)
        "d.struct" => NodeKind::Struct,
        "d.enum" => NodeKind::Enum,
        "d.trait" => NodeKind::Trait,
        "d.fn" => NodeKind::Fn,
        "d.method" => NodeKind::Method,
        "d.mod" => NodeKind::Mod,
        "d.const" => NodeKind::Const,
        "d.type" => NodeKind::Struct, // Go type_spec; refined via @x below
        "d.style" => NodeKind::Style, // CSS selectors
        "d.tag" => NodeKind::Other,   // XML element names
        "d.impl" => NodeKind::Other,  // parent marker, no symbol
        _ => return None,
    })
}

/// Extract one file. Returns `None` when the language has no query table yet
/// (caller falls back) or the source cannot parse.
pub fn extract(lang: TsLang, text: &str) -> Option<TsFile> {
    let q = queries(lang)?;
    let language = language(lang);
    let tree = PARSERS.with(|ps| {
        let mut ps = ps.borrow_mut();
        if !ps.contains_key(&lang) {
            let mut p = Parser::new();
            if p.set_language(&language).is_err() {
                return None;
            }
            ps.insert(lang, p);
        }
        ps.get_mut(&lang).unwrap().parse(text, None)
    })?;
    let root = tree.root_node();
    if root.named_child_count() == 0 && !text.trim().is_empty() {
        return None; // degenerate parse — fall back
    }
    let mut out = TsFile::default();
    out.broken = error_fraction(root) > 0.5;
    let bytes = text.as_bytes();

    // --- defs (each pattern compiled independently) ---
    // (def node, kind, name, detail, parent-qualifier, bases, is marker)
    let mut raw: Vec<(Node, NodeKind, String, String, Option<String>, Vec<String>, bool)> =
        Vec::new();
    // (self-type, trait) pairs for `impl Trait for Type`
    let mut impl_edges: Vec<(String, String)> = Vec::new();
    for (pidx, pattern) in q.defs.iter().chain(q.more_defs).enumerate() {
        with_query(lang, &language, 0, pidx, pattern, |dq| {
            let names: Vec<String> = dq.capture_names().iter().map(|s| s.to_string()).collect();
            let mut cursor = QueryCursor::new();
            let mut matches = cursor.matches(dq, root, bytes);
            while let Some(m) = matches.next() {
            let mut def_node: Option<Node> = None;
            let mut def_kind: Option<NodeKind> = None;
            let mut name_node: Option<Node> = None;
            let mut detail_node: Option<Node> = None;
            let mut qual_node: Option<Node> = None;
            let mut base_nodes: Vec<Node> = Vec::new();
            let mut trait_node: Option<Node> = None;
            let mut self_node: Option<Node> = None;
            let mut is_impl = false;
            for cap in m.captures {
                let cname = &names[cap.index as usize];
                if cname == "n" {
                    if name_node.is_none() {
                        name_node = Some(cap.node); // first name wins (ObjC selectors)
                    }
                } else if cname == "x" {
                    detail_node = Some(cap.node);
                } else if cname == "qn" {
                    qual_node = Some(cap.node);
                } else if cname == "b" {
                    base_nodes.push(cap.node);
                } else if cname == "t" {
                    trait_node = Some(cap.node);
                } else if cname == "y" {
                    self_node = Some(cap.node);
                } else if *cname == "d.impl" {
                    is_impl = true;
                    def_node = Some(cap.node);
                } else if let Some(k) = kind_of(cname) {
                    def_node = Some(cap.node);
                    def_kind = Some(k);
                }
            }
            // `impl Trait for Type` — no symbol, just an edge pair.
            if let (Some(t), Some(y)) = (trait_node, self_node) {
                let (tr, ty) = (text_of(t, text), text_of(y, text));
                if !tr.is_empty() && !ty.is_empty() {
                    impl_edges.push((ty, tr));
                }
            }
            let Some(dn) = def_node else { continue };
            if is_impl {
                if let Some(nn) = name_node {
                    let nm = text_of(nn, text);
                    if !nm.is_empty() {
                        raw.push((dn, NodeKind::Other, nm, String::new(), None, vec![], true));
                    }
                }
                continue;
            }
            let (Some(dk), Some(nn)) = (def_kind, name_node) else {
                continue;
            };
            let name = text_of(nn, text);
            if name.is_empty() {
                continue;
            }
            let detail = detail_node.map(|x| text_of(x, text)).unwrap_or_default();
            let qual = qual_node.map(|x| text_of(x, text)).filter(|s| !s.is_empty());
            let bases: Vec<String> = base_nodes
                .iter()
                .map(|b| text_of(*b, text))
                .map(|s| short_name(&s))
                .filter(|s| !s.is_empty())
                .collect();
                raw.push((dn, dk, name, detail, qual, bases, false));
            }
        });
    }

    // dedupe: several patterns can match one node (plain + heritage).
    // Merge by (range, name): union bases, first qualifier wins.
    let mut merged: Vec<(Node, NodeKind, String, String, Option<String>, Vec<String>, bool)> =
        Vec::new();
    let mut pos: HashMap<(usize, usize, String), usize> = HashMap::new();
    for (dn, dk, name, detail, qual, bases, is_marker) in raw {
        let key = (dn.start_byte(), dn.end_byte(), name.clone());
        if let Some(&i) = pos.get(&key) {
            let m = &mut merged[i];
            for b in bases {
                if !m.5.contains(&b) {
                    m.5.push(b);
                }
            }
            if m.4.is_none() {
                m.4 = qual;
            }
            if m.3.is_empty() {
                m.3 = detail;
            }
        } else {
            pos.insert(key, merged.len());
            merged.push((dn, dk, name, detail, qual, bases, is_marker));
        }
    }
    let raw = merged;

    // parent scopes: type-like defs + impl markers.
    // Mod scopes do NOT method-ify (Julia/OCaml module functions stay Fn).
    let mut scopes: Vec<(usize, usize, String, bool)> = Vec::new();
    for (dn, dk, name, _detail, _qual, _bases, is_marker) in &raw {
        let methodify = *is_marker
            || matches!(dk, NodeKind::Struct | NodeKind::Enum | NodeKind::Trait);
        if methodify || matches!(dk, NodeKind::Mod) {
            scopes.push((dn.start_byte(), dn.end_byte(), name.clone(), methodify));
        }
    }

    // Go type_spec refinement via @x body text + receiver extraction.
    let is_go = lang == TsLang::Go;
    for (dn, dk, name, detail, qual, bases, is_marker) in raw {
        if is_marker {
            continue;
        }
        let mut kind = dk;
        let mut parent: Option<String> = qual.clone();
        if is_go {
            if dk == NodeKind::Struct {
                // @x holds the type body: struct → Struct, interface → Trait.
                let d = detail.trim_start();
                if d.starts_with("interface") {
                    kind = NodeKind::Trait;
                } else if !(d.starts_with("struct")) {
                    kind = NodeKind::Const; // `type X int` etc.
                }
            } else if dk == NodeKind::Method {
                parent = go_receiver(&detail);
            }
        }
        if parent.is_none() {
            // nearest enclosing METHODIFYING scope strictly larger than self
            let mut best = 0usize;
            for (s, e, pname, methodify) in &scopes {
                if !methodify {
                    continue;
                }
                let size = e - s;
                if *s <= dn.start_byte()
                    && dn.end_byte() <= *e
                    && size > best
                    && !(size == dn.end_byte() - dn.start_byte() && pname == &name)
                {
                    best = size;
                    parent = Some(pname.clone());
                }
            }
        }
        let (kind, qualified) = match (kind, &parent) {
            (NodeKind::Fn, Some(p)) => (NodeKind::Method, format!("{p}::{name}")),
            (NodeKind::Method, Some(p)) => (NodeKind::Method, format!("{p}::{name}")),
            (NodeKind::Method, None) => (NodeKind::Fn, name.clone()),
            (k, _) => (k, name.clone()),
        };
        out.items.push(TsItem {
            kind,
            name: name.clone(),
            qualified,
            start_byte: dn.start_byte(),
            end_byte: dn.end_byte(),
            line: dn.start_position().row as u32 + 1,
            parent,
            bases,
            is_test: false,
        });
    }
    for (ty, tr) in impl_edges {
        out.impls.push(TsImpl { ty, tr });
    }

    // --- imports ---
    for (pidx, pattern) in q.imports.iter().enumerate() {
        with_query(lang, &language, 2, pidx, pattern, |iq| {
            let inames: Vec<String> = iq.capture_names().iter().map(|s| s.to_string()).collect();
            let mut cursor = QueryCursor::new();
            let mut matches = cursor.matches(iq, root, bytes);
            while let Some(m) = matches.next() {
                for cap in m.captures {
                    if inames[cap.index as usize] == "i" {
                        let t = text_of(cap.node, text);
                        if !t.is_empty() {
                            out.imports.push(t);
                        }
                    }
                }
            }
        });
    }

    // --- calls ---
    for (pidx, pattern) in q.calls.iter().enumerate() {
        with_query(lang, &language, 1, pidx, pattern, |cq| {
            let cnames: Vec<String> = cq.capture_names().iter().map(|s| s.to_string()).collect();
            let mut cursor = QueryCursor::new();
            let mut matches = cursor.matches(cq, root, bytes);
            while let Some(m) = matches.next() {
            let mut cnode: Option<Node> = None;
            let mut name: Option<String> = None;
            let mut qual: Option<String> = None;
            for cap in m.captures {
                match cnames[cap.index as usize].as_str() {
                    "c" => cnode = Some(cap.node),
                    "cn" => name = Some(text_of(cap.node, text)),
                    "cq" => qual = Some(text_of(cap.node, text)),
                    _ => {}
                }
            }
                if let (Some(cn), Some(n)) = (cnode, name) {
                    if n.is_empty() {
                        continue;
                    }
                    out.calls.push(TsCall {
                        start_byte: cn.start_byte(),
                        qualifier: qual.filter(|s| !s.is_empty()),
                        name: n,
                    });
                }
            }
        });
    }

    // dedupe calls (same site can match several patterns)
    let mut seen = std::collections::HashSet::new();
    out.calls.retain(|c| seen.insert((c.start_byte, c.name.clone(), c.qualifier.clone())));

    Some(out)
}

/// `a::b::C<T>` / `a.b.C` → `C`.
fn short_name(s: &str) -> String {
    let s = s.split('<').next().unwrap_or(s).trim();
    s.rsplit("::").next().unwrap_or(s).rsplit('.').next().unwrap_or(s).trim().to_string()
}

/// `func (s *Store)` / `func (s Store)` → `Store`.
fn go_receiver(detail: &str) -> Option<String> {
    let inner = detail.trim().trim_start_matches('(').trim_end_matches(')');
    for tok in inner.split(|c: char| c == ' ' || c == '\t' || c == ',') {
        let t = tok.trim().trim_start_matches('*').trim_start_matches("[]");
        if t.len() > 1 && t.starts_with(|c: char| c.is_uppercase()) {
            return Some(t.to_string());
        }
    }
    None
}

/// Fraction of the tree covered by ERROR nodes (0.0–1.0).
fn error_fraction(root: Node) -> f64 {
    let total = root.end_byte().max(1) as f64;
    let mut err = 0usize;
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if n.is_error() {
            err += n.end_byte() - n.start_byte();
        } else {
            let mut c = n.walk();
            for child in n.children(&mut c) {
                stack.push(child);
            }
        }
    }
    err as f64 / total
}

/// Enclosing item for a byte offset (smallest containing def).
pub fn enclosing<'a>(items: &'a [TsItem], byte: usize) -> Option<&'a TsItem> {
    let mut best: Option<&TsItem> = None;
    let mut best_size = usize::MAX;
    for it in items {
        if it.start_byte <= byte && byte < it.end_byte {
            let size = it.end_byte - it.start_byte;
            if size < best_size {
                best_size = size;
                best = Some(it);
            }
        }
    }
    best
}

/// Debug helper: S-expression of a snippet's tree (used to author queries
/// for unfamiliar grammars).
pub fn sexp(lang: TsLang, text: &str) -> Option<String> {
    let language = language(lang);
    let mut parser = Parser::new();
    parser.set_language(&language).ok()?;
    let tree = parser.parse(text, None)?;
    Some(tree.root_node().to_sexp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defs(lang: TsLang, src: &str) -> TsFile {
        extract(lang, src).expect("extract must succeed")
    }

    #[test]
    fn rust_items_calls_imports() {
        let f = defs(
            TsLang::Rust,
            "use crate::store::Store;\n\npub struct Store;\nimpl Store {\n  pub fn fresh() -> Store { Store }\n}\npub fn setup() { let _ = Store::fresh(); }\n",
        );
        let names: Vec<(&str, NodeKind)> =
            f.items.iter().map(|i| (i.qualified.as_str(), i.kind)).collect();
        assert!(names.contains(&("Store", NodeKind::Struct)), "{names:?}");
        assert!(names.iter().any(|(n, k)| *k == NodeKind::Method && n.contains("fresh")), "{names:?}");
        assert!(names.contains(&("setup", NodeKind::Fn)), "{names:?}");
        assert!(f.imports.iter().any(|i| i.contains("Store")), "{:?}", f.imports);
        assert!(f.calls.iter().any(|c| c.name == "fresh" && c.qualifier.as_deref() == Some("Store")), "{:?}", f.calls);
    }

    #[test]
    fn python_class_method_call() {
        let f = defs(
            TsLang::Python,
            "from .store import Store\n\nclass Store:\n  def fresh(self):\n    return Store()\n",
        );
        assert!(f.items.iter().any(|i| i.name == "Store" && i.kind == NodeKind::Struct), "{:?}", f.items);
        assert!(f.items.iter().any(|i| i.qualified == "Store::fresh"), "{:?}", f.items);
        assert!(f.calls.iter().any(|c| c.name == "Store"), "{:?}", f.calls);
    }

    #[test]
    fn js_class_and_import() {
        let f = defs(
            TsLang::JavaScript,
            "import { Store } from './store.js';\nclass Store {\n  fresh() { return new Store(); }\n}\n",
        );
        assert!(f.items.iter().any(|i| i.name == "Store"), "{:?}", f.items);
        assert!(f.imports.iter().any(|i| i.contains("store")), "{:?}", f.imports);
    }

    #[test]
    fn go_fn_and_call() {
        let f = defs(
            TsLang::Go,
            "package main\nimport \"fmt\"\nfunc main() { fmt.Println(\"hi\") }\n",
        );
        assert!(f.items.iter().any(|i| i.name == "main"), "{:?}", f.items);
        assert!(f.calls.iter().any(|c| c.name == "Println"), "{:?}", f.calls);
    }

    #[test]
    fn every_table_language_yields_defs() {
        // (lang, snippet, expected symbol, expected kind)
        let cases: &[(TsLang, &str, &str, NodeKind)] = &[
            (TsLang::TypeScript, "class Store {\n  fresh(): Store { return new Store(); }\n}\n", "Store", NodeKind::Struct),
            (TsLang::Java, "class Store {\n  Store fresh() { return new Store(); }\n}\n", "Store", NodeKind::Struct),
            (TsLang::C, "struct Point { int x; };\nint add(int a) { return a; }\n", "Point", NodeKind::Struct),
            (TsLang::Cpp, "class Store {\n  Store fresh() { return Store(); }\n};\n", "Store", NodeKind::Struct),
            (TsLang::CSharp, "class Store {\n  Store Fresh() { return new Store(); }\n}\n", "Store", NodeKind::Struct),
            (TsLang::Ruby, "class Store\n  def fresh\n  end\nend\n", "Store", NodeKind::Struct),
            (TsLang::Bash, "fail() { echo hi; }\n", "fail", NodeKind::Fn),
            (TsLang::Php, "<?php\nclass Store {\n  public function fresh() {}\n}\n", "Store", NodeKind::Struct),
            (TsLang::Scala, "class Store {\n  def fresh(): Store = new Store()\n}\n", "Store", NodeKind::Struct),
            (TsLang::Zig, "const Store = struct {\n  pub fn fresh() Store { return .{}; }\n};\n", "Store", NodeKind::Struct),
            (TsLang::Julia, "module M\nfunction fresh() 1 end\nend\n", "fresh", NodeKind::Fn),
            (TsLang::Groovy, "class Store {\n  def fresh() {}\n}\n", "Store", NodeKind::Struct),
            (TsLang::Pascal, "unit U;\ninterface\ntype TStore = class\nend;\nend.\n", "TStore", NodeKind::Struct),
            (TsLang::Verilog, "module adder(input a, output b);\nendmodule\n", "adder", NodeKind::Mod),
            (TsLang::Fortran, "module m\ncontains\nsubroutine hello()\nend subroutine\nend module\n", "hello", NodeKind::Fn),
            (TsLang::ObjC, "@interface Store : NSObject\n@end\n", "Store", NodeKind::Struct),
            (TsLang::Ocaml, "module Store = struct\nend\n", "Store", NodeKind::Mod),
            (TsLang::PowerShell, "function Get-Store {\n  Get-Item .\n}\n", "Get-Store", NodeKind::Fn),
            (TsLang::Css, ".card { color: red; }\n", ".card", NodeKind::Style),
        ];
        for (lang, src, want, kind) in cases {
            let f = defs(*lang, src);
            assert!(
                f.items.iter().any(|i| i.name == *want && i.kind == *kind),
                "{lang:?}: want {want} [{kind:?}], got {:?}",
                f.items
            );
        }
    }

    #[test]
    fn structured_configs() {
        let f = defs(TsLang::Xml, "<Project>\n  <ItemGroup>\n    <Compile Include=\"a.cs\" />\n  </ItemGroup>\n</Project>\n");
        assert!(f.items.iter().any(|i| i.name == "Project"), "{:?}", f.items);
        assert!(f.items.iter().any(|i| i.name == "Compile"), "{:?}", f.items);
        let f = defs(TsLang::Json, "{\"name\": \"x\", \"scripts\": {\"t\": \"y\"}}\n");
        assert!(f.items.iter().any(|i| i.name == "name"), "{:?}", f.items);
        assert!(f.items.iter().any(|i| i.name == "scripts"), "{:?}", f.items);
        let f = defs(TsLang::Yaml, "jobs:\n  build:\n    runs-on: ubuntu\n");
        assert!(f.items.iter().any(|i| i.name == "jobs"), "{:?}", f.items);
        assert!(f.items.iter().any(|i| i.name == "build"), "{:?}", f.items);
    }

    #[test]
    fn inheritance_captured() {        let f = defs(TsLang::Python, "class Store(Base):\n  pass\n");
        let s = f.items.iter().find(|i| i.name == "Store").unwrap();
        assert!(s.bases.contains(&"Base".to_string()), "{s:?}");
        let f = defs(TsLang::Java, "class Store extends Base {\n}\n");
        let s = f.items.iter().find(|i| i.name == "Store").unwrap();
        assert!(s.bases.contains(&"Base".to_string()), "{s:?}");
        let f = defs(TsLang::Rust, "trait T {}\nstruct S;\nimpl T for S {}\n");
        assert!(f.impls.iter().any(|e| e.ty == "S" && e.tr == "T"), "{:?}", f.impls);
    }

    #[test]
    fn dump_unfamiliar_grammars() {
        // Prints S-expressions so queries can be authored for the remaining
        // grammars. Run with --nocapture and read the output.
        let cases: &[(TsLang, &str)] = &[
            (TsLang::Scala, "class Store {\n  def fresh(): Store = new Store()\n}\n"),
            (TsLang::Zig, "const Store = struct {\n  pub fn fresh() Store { return .{}; }\n};\n"),
            (TsLang::Julia, "module M\nstruct Store end\nfunction fresh() Store() end\nend\n"),
            (TsLang::PowerShell, "function Get-Store {\n  Get-Item .\n}\n"),
            (TsLang::Php, "<?php\nclass Store {\n  public function fresh() { return new Store(); }\n}\n"),
            (TsLang::Ruby, "class Store < Base\n  def fresh\n    Store.new\n  end\nend\n"),
            (TsLang::Java, "import a.B;\nclass Store extends Base {\n  Store fresh() { return new Store(); }\n}\n"),
            (TsLang::CSharp, "using System;\nclass Store {\n  Store Fresh() { return new Store(); }\n}\n"),
        ];
        for (lang, src) in cases {
            println!("=== {lang:?} ===\n{}\n", sexp(*lang, src).unwrap_or_default());
        }
        let more: &[(TsLang, &str)] = &[
            (TsLang::TypeScript, "import { A } from './a';\ninterface Box {\n  v: number;\n}\ntype Name = string;\nclass Store implements Box {\n  v = 0;\n  fresh(): Store { return new Store(); }\n}\nfunction top() { return new Store().fresh(); }\n"),
            (TsLang::C, "#include <stdio.h>\nstruct Point { int x; };\nint add(int a) { return add(a); }\n"),
            (TsLang::Cpp, "#include <x.h>\nnamespace N {\nclass Store : public Base {\n  Store fresh() { return Store(); }\n};\n}\n"),
            (TsLang::Bash, "source ./lib.sh\nfail() { echo hi; }\nfail\n"),
            (TsLang::Php, "<?php\nrequire 'a.php';\nfunction top() { return strlen('x'); }\nStore::fresh();\n"),
            (TsLang::Scala, "import a.B\nclass Store extends Base {\n  def fresh(): Store = Store.make()\n}\n"),
            (TsLang::Zig, "const std = @import(\"std\");\nfn main() void { _ = std.io; }\n"),
            (TsLang::Julia, "using Pkg\nfunction f(x) g(x) end\n"),
            (TsLang::Groovy, "import a.B\nclass Store {\n  def fresh() { Store.make() }\n}\n"),
            (TsLang::Css, ".card { color: red; }\n#nav .item:hover { margin: 0; }\n"),
            (TsLang::PowerShell, "using module M\n. ./lib.ps1\nfunction Get-Store { Get-Item $x }\n"),
            (TsLang::Fortran, "module m\ncontains\nsubroutine hello() \ncall world()\nend subroutine\nend module\n"),
            (TsLang::Pascal, "unit U;\ninterface\ntype TStore = class\n  procedure Fresh;\nend;\nimplementation\nprocedure TStore.Fresh; begin end;\nend.\n"),
            (TsLang::Verilog, "module adder(input a, output b);\nassign b = a;\nendmodule\n"),
            (TsLang::ObjC, "#import <F/F.h>\n@interface Store : NSObject\n- (void)fresh;\n@end\n@implementation Store\n- (void)fresh {}\n@end\n"),
            (TsLang::Xml, "<Project><PackageReference Include=\"X\" Version=\"1.0\" /></Project>\n"),
            (TsLang::Ocaml, "module Store = struct\n  let fresh () = fresh ()\nend\n"),
        ];
        for (lang, src) in more {
            println!("=== {lang:?} ===\n{}\n", sexp(*lang, src).unwrap_or_default());
        }
        let more2: &[(TsLang, &str)] = &[
            (TsLang::Xml, "<Project>\n  <ItemGroup>\n    <Compile Include=\"a.cs\" />\n  </ItemGroup>\n</Project>\n"),
            (TsLang::Json, "{\"name\": \"x\", \"scripts\": {\"t\": \"y\"}}\n"),
            (TsLang::Yaml, "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"),
        ];
        for (lang, src) in more2 {
            println!("=== {lang:?} ===\n{}\n", sexp(*lang, src).unwrap_or_default());
        }
    }
}
