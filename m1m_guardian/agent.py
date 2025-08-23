"""Systemd entrypoint module.
ExecStart invokes: python -m m1m_guardian.agent --config /path/to/config.yaml
This simply delegates to main.main() which parses --config.
"""
from .main import main

if __name__ == "__main__":  # pragma: no cover
    main()

