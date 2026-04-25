from __future__ import annotations

from app.signatures import render_fail2ban_filter


def main() -> int:
    print(render_fail2ban_filter(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
