# Vortex Plugin SDK

Welcome to the Vortex Plugin SDK. This directory provides the base classes and documentation for developing custom offensive security plugins.

## Plugin Types

1. **ScannerPlugin**: For active vulnerability fuzzing. Inherit from `ScannerPlugin` and implement the `run` method.
2. **ExploitPlugin**: For post-exploitation and verification. Inherit from `ExploitPlugin` and implement the `verify` method.
3. **TemplatePlugin**: For custom scanning engines.

## Workflow

1. Create a new Python file in the `plugins/` directory.
2. Define a class that inherits from one of the SDK base classes.
3. Implement the required methods (`name`, `run`, `verify`, etc.).
4. Vortex will automatically discover and load your plugin at runtime.

## Example

```python
from sdk.base_plugin import ScannerPlugin

class MyCustomScanner(ScannerPlugin):
    name = "My Custom Vulnerability"
    
    def run(self, http, endpoint, analyzer, evidence):
        # Your scanning logic here
        pass
```
