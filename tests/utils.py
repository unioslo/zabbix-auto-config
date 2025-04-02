from __future__ import annotations

from contextlib import contextmanager
from typing import Generator
from typing import TypeVar

from pydantic import BaseModel

BaseModelT = TypeVar("BaseModelT", bound=BaseModel)


@contextmanager
def disable_assignment_validation(
    model: BaseModelT,
) -> Generator[BaseModelT, None, None]:
    """Temporarily disable `validate_assignment` for a Pydantic model."""
    orig = model.model_config.get("validate_assignment")
    model.model_config["validate_assignment"] = False
    try:
        yield model
    finally:
        # Revert to original value (if any) or remove the key
        if orig is not None:
            model.model_config["validate_assignment"] = orig
        else:
            model.model_config.pop("validate_assignment", None)
