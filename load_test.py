import pkgutil
import inspect
import importlib
import os
import sys

def load_plugins():
    plugins = []
    plugins_dir = os.path.join(os.path.dirname(__file__), "plugins")
    if not os.path.exists(plugins_dir): return plugins
    sys.path.insert(0, os.path.dirname(__file__))

    for root, dirs, files in os.walk(plugins_dir):
        for file in files:
            if file.endswith(".py") and not file.startswith("__"):
                module_name = "plugins." + file[:-3]
                try:
                    module = importlib.import_module(module_name)
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if hasattr(obj, "name") and hasattr(obj, "run") and obj.__module__ == module_name:
                            if obj.__name__ != "BasePlugin":
                                plugins.append(obj())
                except Exception as e:
                    print(f"Error loading {module_name}: {e}")
    return plugins

print(len(load_plugins()))
