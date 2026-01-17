"""
Pytest configuration for lcore-sdk Python package.

Uses src-layout: imports from 'src' directory are available as 'lcore'.
"""

import sys
from pathlib import Path

# Add src directory to path and alias it as 'lcore'
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir.parent))

# Create module alias so 'from lcore import ...' works
import importlib
import importlib.util

# Load src as lcore module
spec = importlib.util.spec_from_file_location(
    "lcore",
    src_dir / "__init__.py",
    submodule_search_locations=[str(src_dir)]
)
if spec and spec.loader:
    lcore = importlib.util.module_from_spec(spec)
    sys.modules["lcore"] = lcore
    spec.loader.exec_module(lcore)

    # Also register submodules
    for submodule in ["did", "device", "client", "models"]:
        submod_path = src_dir / f"{submodule}.py"
        if submod_path.exists():
            sub_spec = importlib.util.spec_from_file_location(
                f"lcore.{submodule}",
                submod_path
            )
            if sub_spec and sub_spec.loader:
                sub_mod = importlib.util.module_from_spec(sub_spec)
                sys.modules[f"lcore.{submodule}"] = sub_mod
                sub_spec.loader.exec_module(sub_mod)
                setattr(lcore, submodule, sub_mod)
