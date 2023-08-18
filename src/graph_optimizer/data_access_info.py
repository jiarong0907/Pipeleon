from __future__ import annotations
from dataclasses import dataclass
from typing import List

from ir.action_parameter import ActionParam, ExpressionParam, FieldParam, HeaderParam, HexStrParam, RuntimeDataParam

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ir.match_key import MatchKey


@dataclass
class DataAccessInfo:
    match_key: List[MatchKey]
    action_read: List[ActionParam]
    action_write: List[ActionParam]
    has_entry_insertion: bool

    @classmethod
    def _exception_handler(cls, param: ActionParam):
        if isinstance(param, RuntimeDataParam) or isinstance(param, HexStrParam) or isinstance(param, ExpressionParam):
            raise Exception("DataAccessInfo should not record constants or expressions")
        else:
            raise Exception("Unexpected action parameter instance in DataAccessInfo")

    def _match_key_written_by_other(self, other: "DataAccessInfo") -> bool:
        """Check whether the match keys of the current object is written by the actions
        of the other object.
        """
        for mkey in self.match_key:
            mk_target = mkey._get_target()
            for wt in other.action_write:
                if isinstance(wt, FieldParam):
                    if wt.value == mk_target:
                        return True
                elif isinstance(wt, HeaderParam):
                    if wt.value == mk_target[0]:
                        return True
                else:
                    self._exception_handler(wt)
        return False

    @classmethod
    def _field_written_by_other(cls, field: FieldParam, other: "DataAccessInfo") -> bool:
        """Check whether a field parameter of the current object is written by the actions
        of the other object.
        """
        for wt in other.action_write:
            if isinstance(wt, FieldParam):
                if wt.value == field.value:
                    return True
            elif isinstance(wt, HeaderParam):
                if wt.value == field.value[0]:
                    return True
            else:
                cls._exception_handler(wt)
        return False

    @classmethod
    def _header_written_by_other(cls, header: HeaderParam, other: "DataAccessInfo") -> bool:
        """Check whether a header parameter of the current object is written by the actions
        of the other object.
        """
        for wt in other.action_write:
            if isinstance(wt, FieldParam):
                if header.value in wt.value:
                    return True
            elif isinstance(wt, HeaderParam):
                if header.value == wt.value:
                    return True
            else:
                cls._exception_handler(wt)
        return False

    @classmethod
    def _field_read_by_other(cls, field: FieldParam, other: "DataAccessInfo") -> bool:
        """Check whether a field parameter of the current object is read by the actions
        of the other object.
        """
        for rd in other.action_read:
            if isinstance(rd, FieldParam):
                if rd.value == field.value:
                    return True
            elif isinstance(rd, HeaderParam):
                if rd.value == field.value[0]:
                    return True
            else:
                cls._exception_handler(rd)
        for mk in other.match_key:
            if field.value == mk._get_target():
                return True
        return False

    @classmethod
    def _header_read_by_other(cls, header: HeaderParam, other: "DataAccessInfo") -> bool:
        """Check whether a header parameter of the current object is read by the actions
        of the other object.
        """
        for rd in other.action_read:
            if isinstance(rd, FieldParam):
                if header.value in rd.value:
                    return True
            elif isinstance(rd, HeaderParam):
                if header.value == rd.value:
                    return True
            else:
                cls._exception_handler(rd)
        for mk in other.match_key:
            if header.value in mk._get_target():
                return True
        return False

    def _has_dependency_with(self, other: "DataAccessInfo") -> bool:
        """Check whether there is dependency between two DataAccessInfo object (two tables).

        There are three dependency types:
            (1) read-write: tab2 writes variables read by tab1
            (2) write-read: tab2 read variables written by tab1
            (3) write-write: tab1 writes variables later will be written by tab2 again
        """

        """Check (1) read-write
        """
        if self._match_key_written_by_other(other):
            return True
        for rd in self.action_read:
            if isinstance(rd, FieldParam):
                if self._field_written_by_other(rd, other):
                    return True
            elif isinstance(rd, HeaderParam):
                if self._header_written_by_other(rd, other):
                    return True
            else:
                self._exception_handler(rd)

        """Check (2) write-read
        """
        for wt in self.action_write:
            if isinstance(wt, FieldParam):
                if self._field_read_by_other(wt, other):
                    return True
            elif isinstance(wt, HeaderParam):
                if self._header_read_by_other(wt, other):
                    return True
            else:
                self._exception_handler(wt)

        """Check (3) write-write
        """
        for wt in self.action_write:
            if isinstance(wt, FieldParam):
                if self._field_written_by_other(wt, other):
                    return True
            elif isinstance(wt, HeaderParam):
                if self._header_written_by_other(wt, other):
                    return True
            else:
                self._exception_handler(wt)

        """Check (4) table entry install
        """
        if self.has_entry_insertion or other.has_entry_insertion:
            return True

        return False
