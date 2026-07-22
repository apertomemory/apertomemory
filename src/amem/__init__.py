"""ApertoMemory — portable, client-side-encrypted, user-owned AI memory."""
__version__ = "0.1.3"
from .objects import MemoryObject, seal, open_sealed
from .vault import Vault
