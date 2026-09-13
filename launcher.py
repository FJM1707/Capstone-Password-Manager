"""Standalone entry point for PyInstaller. Uses an absolute import (not the
package's relative `from .gui import main`) since this script runs outside
the package context when frozen into an executable."""

from password_manager.gui import main

if __name__ == "__main__":
    main()
