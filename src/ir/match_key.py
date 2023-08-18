from __future__ import annotations
from dataclasses import dataclass
import enum
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from ir.irgraph import IrGraph


class MatchType(enum.Enum):
    EXACT = "exact"
    TERNARY = "ternary"
    RANGE = "range"
    LPM = "lpm"


@dataclass
class MatchKey:
    header: str
    match_type: MatchType
    global_mask: Optional[int]
    name: str

    def __hash__(self) -> int:
        return hash(self.name)

    def __str__(self) -> str:
        return self.name

    def __eq__(self, other: MatchKey) -> bool:
        return (
            self.header == other.header
            and self.match_type == other.match_type
            and self.global_mask == other.global_mask
            and self.name == other.name
        )

    def _get_target(self) -> List[str]:
        # only split the first . because user metadata will use .
        assert len(self.header.split(".")) <= 3, f"There should be at most two . in header"
        return self.header.split(".", 1)

    def _get_key_length(self, irgraph: IrGraph) -> int:
        """Get the bit length of the key"""
        key_target = self._get_target()
        assert len(key_target) == 2, (
            f"The target should have header_name, header_field two elements, " f"but got {key_target}"
        )
        all_headers = irgraph.headers
        hdr_id = -1
        for h in all_headers:
            if h.name == key_target[0]:
                hdr_id = h.id
        assert hdr_id != -1, f"Header {key_target[0]} was not found in irgraph headers."

        all_header_types = irgraph.header_types
        for ht in all_header_types:
            if ht.id == hdr_id:
                for f in ht.fields:
                    if f.name == key_target[1]:
                        return f.length
        raise Exception(f"Key {self.name}, {key_target[1]} was not found in header types.")

    def _p4cir2json(self):
        return {
            "target": self._get_target(),
            "match_type": self.match_type.value,
            "mask": self.global_mask,
            "name": self.name,
        }

    @classmethod
    def _p4cjson2ir(cls, jsonkey) -> List["MatchKey"]:
        irkey: List[MatchKey] = []
        for k in jsonkey:
            irkey.append(
                MatchKey(
                    header=".".join(k["target"]),
                    match_type=MatchType(k["match_type"]),
                    global_mask=k["mask"],
                    name=k["name"],
                )
            )
        return irkey
