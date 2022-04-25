# Store singleton-like application state

# Prevent circular imports
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import tab_view

tabview: "tab_view.TabView" = None
