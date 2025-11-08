# Sanity import tests for recent changes using importlib to avoid unused warnings
import sys, os
import importlib
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
print('Python:', sys.version)

try:
    m = importlib.import_module('LLMs.multi_llm_orchestrator')
    _h = getattr(m, '_apply_hygiene', None)
    print('Imported LLMs.multi_llm_orchestrator; _apply_hygiene callable =', callable(_h))
except ImportError as e:
    print('Import LLMs.multi_llm_orchestrator failed:', type(e).__name__, str(e))

try:
    fc = importlib.import_module('Normalizer.fp_classifier')  # type: ignore
    print('Imported Normalizer.fp_classifier; module =', getattr(fc, '__name__', 'unknown'))
except ImportError as e:
    print('Import Normalizer.fp_classifier failed:', type(e).__name__, str(e))

try:
    norm = importlib.import_module('Normalizer.normalize')  # type: ignore
    print('Imported Normalizer.normalize; module =', getattr(norm, '__name__', 'unknown'))
except ImportError as e:
    print('Import Normalizer.normalize failed:', type(e).__name__, str(e))

try:
    cli_mod = importlib.import_module('cli')  # type: ignore
    print('Imported cli; module =', getattr(cli_mod, '__name__', 'unknown'))
except ImportError as e:
    print('Import cli failed:', type(e).__name__, str(e))
