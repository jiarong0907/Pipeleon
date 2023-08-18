from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List

from commons.types import ActionData, ActionName


class EntryMatchKeyParam(ABC):
    """This Match Key here is for TableEntry, not for Table.

    Also the MatchKeyParam means one single parameter in the match key, and the
    match key is a list of such parameters."""

    def __init__(self, type: str):
        self._type: str = type

    @property
    def type(self) -> str:
        return self._type

    @abstractmethod
    def _p4cir2json(self):
        raise NotImplementedError()

    @classmethod
    @abstractmethod
    def _p4cjson2ir(cls, json: Dict[str, Any]) -> "EntryMatchKeyParam":
        raise NotImplementedError()


class ExactEntryMatchKeyParam(EntryMatchKeyParam):
    def __init__(self, type: str, key: str):
        super().__init__(type)
        self._key: str = key

    @property
    def key(self) -> str:
        return self._key

    def _p4cir2json(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "key": self.key,
        }

    @classmethod
    def _p4cjson2ir(cls, json: Dict[str, Any]) -> "ExactEntryMatchKeyParam":
        return cls(type=json["type"], key=json["key"])


class LpmEntryMatchKeyParam(EntryMatchKeyParam):
    def __init__(self, type: str, key: str, prefix_length: int):
        super().__init__(type)
        self._key: str = key
        self._prefix_length: int = prefix_length

    @property
    def key(self) -> str:
        return self._key

    @property
    def prefix_length(self) -> int:
        return self._prefix_length

    def _p4cir2json(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "key": self.key,
            "prefix_length": self.prefix_length,
        }

    @classmethod
    def _p4cjson2ir(cls, json: Dict[str, Any]) -> "LpmEntryMatchKeyParam":
        return cls(type=json["type"], key=json["key"], prefix_length=json["prefix_length"])


class TernaryEntryMatchKeyParam(EntryMatchKeyParam):
    def __init__(self, type: str, key: str, mask: str):
        super().__init__(type)
        self._key: str = key
        self._mask: str = mask

    @property
    def key(self) -> str:
        return self._key

    @key.setter
    def key(self, new_key):
        self._key = new_key

    @property
    def mask(self) -> str:
        return self._mask

    @mask.setter
    def mask(self, new_mask):
        self._mask = new_mask

    def _p4cir2json(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "key": self.key,
            "mask": self.mask,
        }

    @classmethod
    def _p4cjson2ir(cls, json: Dict[str, Any]) -> "TernaryEntryMatchKeyParam":
        return cls(type=json["type"], key=json["key"], mask=json["mask"])


class ValidEntryMatchKeyParam(EntryMatchKeyParam):
    def __init__(self, type: str, key: int):
        super().__init__(type)
        self._key: int = key  # Note this key for Valid match key is int not str

    @property
    def key(self) -> int:
        return self._key

    def _p4cir2json(self) -> Dict[str, Any]:
        return {
            "type": self._type,
            "key": self._key,
        }

    @classmethod
    def _p4cjson2ir(cls, json: Dict[str, Any]) -> "ValidEntryMatchKeyParam":
        return cls(type=json["type"], key=json["key"])


class RangeEntryMatchKeyParam(EntryMatchKeyParam):
    def __init__(self, type: str, start: str, end: str):
        super().__init__(type)
        self._start: str = start
        self._end: str = end

    @property
    def start(self) -> str:
        return self._start

    @property
    def end(self) -> str:
        return self._end

    def _p4cir2json(self) -> Dict[str, Any]:
        return {
            "type": self._type,
            "start": self._start,
            "end": self._end,
        }

    @classmethod
    def _p4cjson2ir(cls, json: Dict[str, Any]) -> "RangeEntryMatchKeyParam":
        return cls(type=json["type"], start=json["start"], end=json["end"])


class EntryMatchKeyParamBuilder:
    ENTRY_MATCH_KEY_PARAM_TYPE_STR_TO_CLS = {
        "EXACT": ExactEntryMatchKeyParam,
        "LPM": LpmEntryMatchKeyParam,
        "TERNARY": TernaryEntryMatchKeyParam,
        "VALID": ValidEntryMatchKeyParam,
        "RANGE": RangeEntryMatchKeyParam,
    }

    @classmethod
    def build_entry_match_key_param(cls, json: Dict[str, Any]) -> EntryMatchKeyParam:
        entry_match_key_param_cls = cls.ENTRY_MATCH_KEY_PARAM_TYPE_STR_TO_CLS[json["type"]]
        return entry_match_key_param_cls._p4cjson2ir(json)


EntryMatchKey = List[EntryMatchKeyParam]


@dataclass
class TableEntry:
    action_name: ActionName
    action_data: List[ActionData]
    match_key: EntryMatchKey
    priority: int

    def _p4cir2json(self) -> Dict[str, Any]:
        return {
            "action_name": self.action_name,
            "action_data": self.action_data,
            "match_key": [match_key_param._p4cir2json() for match_key_param in self.match_key],
            "priority": self.priority,
        }

    @classmethod
    def _p4cjson2ir(cls, json: Dict[str, Any]) -> "TableEntry":
        return cls(
            action_name=json["action_name"],
            action_data=json["action_data"],
            match_key=[
                EntryMatchKeyParamBuilder.build_entry_match_key_param(json_match_key_param)
                for json_match_key_param in json["match_key"]
            ],
            priority=json["priority"],
        )
