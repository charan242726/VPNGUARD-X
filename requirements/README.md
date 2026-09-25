# Dependency locks

`core.lock` is sufficient for deterministic parsing, CGII, policy, risk, remediation, reports, and the standard-library test suite. `all.lock` adds model training, API, dashboard, and development tools.

The versions are deliberately fixed, not claimed to be the newest. Freeze platform-specific hashes with your institutional package mirror before a benchmark release; PyTorch wheel selection depends on CPU/CUDA platform. Record `pip freeze`, Python version, OS/kernel, and accelerator/driver details in each training manifest.
