"""Forbidden operations for code execution guardrails."""

# Modules that are forbidden in guarded execution
FORBIDDEN_MODULES = {
    "os", "sys", "subprocess", "socket", "requests", "urllib",
    "pickle", "shelve", "marshal", "importlib", "builtins",
    "ctypes", "multiprocessing", "threading", "concurrent",
    "tempfile", "shutil", "glob", "pathlib", "io", "fileinput",
}

# Builtins that are forbidden to call
FORBIDDEN_BUILTINS = {
    "exec", "eval", "compile", "__import__", "open", "input",
    "breakpoint", "globals", "locals", "vars", "dir",
    "memoryview", "type", "object", "class", "delattr", "setattr",
    "getattr", "hasattr", "property", "super",
}

# Dangerous attribute access patterns
DANGEROUS_ATTRIBUTES = {
    "__dict__", "__class__", "__bases__", "__subclasses__",
    "__mro__", "__init__", "__new__", "__getattribute__",
}

# Safe builtins allowed in guarded execution
SAFE_BUILTINS = {
    # Math operations
    "abs", "min", "max", "sum", "len", "round", "pow",
    "divmod", "int", "float", "complex",

    # Type operations (safe subset)
    "bool", "str", "list", "tuple", "set", "dict", "frozenset",
    "bytes", "bytearray",

    # Iteration
    "range", "enumerate", "zip", "map", "filter", "sorted",
    "reversed", "iter", "next", "slice",

    # Comparison
    "all", "any", "isinstance", "issubclass",

    # String formatting
    "format", "repr", "ascii", "chr", "ord",

    # Constants
    "True", "False", "None",

    # Exception handling (read-only)
    "Exception", "StopIteration", "ValueError", "TypeError",
    "IndexError", "KeyError", "ZeroDivisionError",
    "AttributeError", "RuntimeError",
}
