# Third-party notices

GOVP's Python package installs its dependencies separately. Standalone GOVP
binaries bundle a Python runtime and third-party components selected by the
release workflow. Recipients should retain this notice with redistributed
binaries.

The v0.1.8 release toolchain directly selects:

| Component | License |
| --- | --- |
| Python | Python Software Foundation License |
| certifi | MPL-2.0 |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| OpenSSL, bundled through cryptography wheels where applicable | Apache-2.0 |
| cffi | MIT-0 |
| pycparser | BSD-3-Clause |
| PyInstaller | GPL-2.0-or-later with the PyInstaller bootloader exception |
| altgraph | MIT |
| macholib, macOS builds | MIT |
| pefile, Windows builds | MIT |
| pywin32-ctypes, Windows builds | BSD-3-Clause |

The authoritative license text for each component is distributed by that
component's upstream package. PyInstaller's exception permits distribution of
executables produced with PyInstaller without imposing the GPL on GOVP.

This notice is informational and does not change GOVP's Apache-2.0 license. The
resolved dependency set in the release logs is authoritative for a particular
platform artifact and must be reviewed before redistribution.
