# A wrapper for warnings. More background can be found in the following docs:
# https://docs.python.org/3.9/library/exceptions.html#DeprecationWarning
# https://www.lesinskis.com/python_deprecation_tutorial.html

import warnings

warnings.simplefilter("default")


def raise_deprecated_warning(mesg: str):
    warnings.warn(mesg, DeprecationWarning, stacklevel=2)
