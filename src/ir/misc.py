""""
Misc functions for ir
"""

from collections import OrderedDict
from collections.abc import Iterable
from typing import Union, OrderedDict as TypingOrderedDict


def dict_to_desc(od: TypingOrderedDict[str, Union[str, int, float, Iterable]]) -> str:
    """translates odered dict to html code"""
    text = ""
    for k, v in od.items():
        if isinstance(v, (str, int, float)):
            vtxt = str(v)
        elif isinstance(v, Iterable):
            vtxt = "<br>".join([x for x in v])
        else:
            raise TypeError(v)
        text += f"<b>{k}</b><br>{vtxt}<br><br>"
    return text
