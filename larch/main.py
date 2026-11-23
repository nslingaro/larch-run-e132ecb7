"""ASGI entry point: ``larch.main:app``. Configuration comes from LARCH_* variables."""

from larch.app import create_app

app = create_app()
