# Visualization Tools

The `viz` package provides interactive widgets for exploring protocol flows and key
derivations inside Jupyter notebooks.

```python
from cryptography_suite.viz import HandshakeFlowWidget

widget = HandshakeFlowWidget(["client hello", "server hello", "key exchange"])
widget
```

Widgets can also be used headless by exporting their underlying data.
