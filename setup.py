from distutils.core import setup
import py2exe
"""
options = {
    'py2exe': {
        'includes': ['module_name1', 'module_name2', ...]
    }
}
"""
setup(console=["dump.py"])