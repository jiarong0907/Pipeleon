from dataclasses import dataclass
from typing import List

from commons.types import HeaderId, HeaderName, tHeaderType, tHeaderField


@dataclass
class Header:
    name: HeaderName
    id: HeaderId
    header_type: tHeaderType
    metadata: bool
    pi_omit: bool

    def _p4cir2json(self):
        return {
            "name": self.name,
            "id": self.id,
            "header_type": self.header_type,
            "metadata": self.metadata,
            "pi_omit": self.pi_omit,
        }

    @classmethod
    def _p4cjson2ir(cls, json) -> "Header":
        return Header(
            name=json["name"],
            id=json["id"],
            header_type=json["header_type"],
            metadata=json["metadata"],
            pi_omit=json["pi_omit"],
        )


@dataclass
class HeaderField:
    name: tHeaderField
    length: int
    flag: bool

    def _p4cir2json(self):
        return [self.name, self.length, self.flag]

    @classmethod
    def _p4cjson2ir(cls, json) -> "HeaderField":
        return HeaderField(name=json[0], length=json[1], flag=json[2])


@dataclass
class HeaderType:
    name: HeaderName
    id: HeaderId
    fields: List[HeaderField]

    def _p4cir2json(self):
        return {"name": self.name, "id": self.id, "fields": [f._p4cir2json() for f in self.fields]}

    @classmethod
    def _p4cjson2ir(cls, json) -> "HeaderType":
        fields_list: List[HeaderField] = []
        for field_json in json["fields"]:
            fields_list.append(HeaderField._p4cjson2ir(field_json))

        return HeaderType(name=json["name"], id=json["id"], fields=fields_list)
