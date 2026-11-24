"""Shared pytest configuration: Hypothesis profiles.

Profiles are registered at import time (before the ``--hypothesis-profile`` option is applied):

* ``ci``  (default): max_examples=200, deadline=None. Same strength as the explicit decorators.
* ``dev``: max_examples=25, deadline=None. Fast on-save runs.

Select with ``HYPOTHESIS_PROFILE=dev`` or ``pytest --hypothesis-profile=dev``.

Explicit ``@settings(...)`` decorators override the loaded profile, so the profile mainly affects
tests without an explicit ``@settings`` and stateful tests. To make ``dev`` effective for the
decorated tests as well, ``pytest_collection_modifyitems`` caps ``max_examples`` on every ``@given``
test, but only while the active profile is ``dev``. The ``ci`` profile never alters any test.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from hypothesis import settings

DEV_MAX_EXAMPLES = 25

settings.register_profile("dev", max_examples=DEV_MAX_EXAMPLES, deadline=None)
settings.register_profile("ci", max_examples=200, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Cap ``max_examples`` of decorated ``@given`` tests when the ``dev`` profile is active."""
    # The pytest option is applied after conftest import, so read the *effective* choice here.
    if settings.get_current_profile_name() != "dev":
        return
    for item in items:
        obj: Any = getattr(item, "obj", None)
        handle = getattr(obj, "hypothesis", None)
        if handle is None:
            continue
        current = getattr(obj, "_hypothesis_internal_use_settings", None)
        if current is not None and current.max_examples > DEV_MAX_EXAMPLES:
            obj._hypothesis_internal_use_settings = settings(current, max_examples=DEV_MAX_EXAMPLES)
