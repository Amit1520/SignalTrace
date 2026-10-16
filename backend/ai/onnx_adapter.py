from .runtime.adapter import OnnxRuntimeExplainer

OnnxLocalExplainer = OnnxRuntimeExplainer

__all__ = ["OnnxLocalExplainer", "OnnxRuntimeExplainer"]
