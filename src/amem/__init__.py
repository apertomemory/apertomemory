"""ApertoMemory — portable, client-side-encrypted, user-owned AI memory."""
__version__ = "0.2.1"   # kept in step with pyproject.toml by tests/test_version.py
from .objects import MemoryObject, seal, open_sealed
from .vault import Vault
