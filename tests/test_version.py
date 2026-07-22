"""The module version and the packaging version must not drift apart.

They did once: 0.2.1 shipped to PyPI with __version__ = "0.1.3" inside,
because a directory-wide copy overwrote the bumped file. pip reported one
version and `import amem` reported another.
"""
import re
from pathlib import Path

import amem


def test_module_version_matches_pyproject():
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(),
                         re.M).group(1)
    assert amem.__version__ == declared, (
        f"__init__.py says {amem.__version__}, pyproject.toml says {declared}")
