_LAZY = {
    'messenger_api': ('network.api', 'messenger_api'),
    'make_server_request_async': ('network.api', 'make_server_request_async'),
    'Contact': ('network.models', 'Contact'),
}


def __getattr__(name):
    if name in _LAZY:
        import importlib
        module_name, attr = _LAZY[name]
        return getattr(importlib.import_module(module_name), attr)
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
