"""Sentinel V5 hello-python example using the bundled SDK."""
from __future__ import annotations

import re
import sys
from pathlib import Path

# Python -I does not import from the script's directory or PYTHONPATH.
# Both source checkouts and Sentinel installations provide sdk/python/.
sdk_dir = Path(__file__).resolve().parents[2] / "sdk" / "python"
sys.path.insert(0, str(sdk_dir))

from sentinel_sdk import Plugin, Request, Result  # noqa: E402

plugin = Plugin()


@plugin.command("greet")
def greet(request: Request) -> Result:
    raw = request.args.get("name", request.actor)
    name = re.sub(r"[^a-zA-Z0-9 _-]", "", raw).strip()[:64] or "friend"
    return Result(
        view="greeting",
        values={"name": name, "language": "Python 3"},
    )


if __name__ == "__main__":
    plugin.serve()
