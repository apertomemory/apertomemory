"""ApertoMemory — portable, client-side-encrypted, user-owned AI memory."""
__version__ = "0.2.0"
from .objects import MemoryObject, seal, open_sealed
from .vault import Vault
