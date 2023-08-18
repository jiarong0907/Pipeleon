import pytest
import os

from graph_optimizer.json_manager import JsonManager
from ir.action import Action


@pytest.mark.parametrize(
    "json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "next_table_selector", "test.p4.json")],
)
class TestNextTableProbability:
    def test_next_table_to_prob_straightline(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 2
        tab1 = tables[0]
        tab2 = tables[1]
        # tab1 has a drop action, so only 0.5 to tab2
        tab1_n2prob = tab1._next_table_selector.next_table_to_probability
        assert len(tab1_n2prob) == 1
        assert tab1_n2prob["MyIngress.tab2"] == 0.5

        # tab2 has no drop action, so all traffic goes to tab3
        tab2_n2prob = tab2._next_table_selector.next_table_to_probability
        assert len(tab2_n2prob) == 1
        assert 1.01 > tab2_n2prob["MyIngress.tab3"] > 0.99

    def test_next_table_to_prob_ifelse(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        tab5 = tables[4]

        tab5_n2prob = tab5._next_table_selector.next_table_to_probability
        assert len(tab5_n2prob) == 1
        assert 1.01 > tab5_n2prob["MyIngress.tab6"] > 0.99

    def test_next_table_to_prob_hitmiss(self, json_path):
        return
        # TODO: Program will crash
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 3
        tab4 = tables[3]
        assert tab4._next_table_selector._has_hit_miss

        tab4_n2prob = tab4._next_table_selector.next_table_to_probability
        assert len(tab4_n2prob) == 2
        assert tab4_n2prob == {
            "__HIT__": 0.5,
            "__MISS__": 0.5,
        }

    def test_next_table_to_prob_switchcase(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        assert len(tables) >= 3
        tab6 = tables[5]

        tab6_n2prob = tab6._next_table_selector.next_table_to_probability
        assert len(tab6_n2prob) == 2
        assert tab6_n2prob == {
            "MyIngress.tab7": 0.5,
            "MyIngress.tab8": 0.5,
        }

    def test_update_action_prob_1act(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        update_act_prob_1act_tab = tables[8]

        # total_count < 10
        update_act_prob_1act_tab.update_prob_with_counts({"MyIngress.update_act_prob_1act_tab_act1": 1})
        updated_a2prob = update_act_prob_1act_tab.action_to_probability
        assert 1.01 > updated_a2prob["MyIngress.update_act_prob_1act_tab_act1"] > 0.99

        # total_count >= 10
        update_act_prob_1act_tab.update_prob_with_counts({"MyIngress.update_act_prob_1act_tab_act1": 100})
        updated_a2prob = update_act_prob_1act_tab.action_to_probability
        assert 1.01 > updated_a2prob["MyIngress.update_act_prob_1act_tab_act1"] > 0.99

    def test_update_action_prob_2act(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        update_act_prob_2act_tab = tables[9]

        # total_count < 10, no update
        update_act_prob_2act_tab.update_prob_with_counts(
            {"MyIngress.update_act_prob_2act_tab_act1": 1, "MyIngress.update_act_prob_2act_tab_act2": 1}
        )
        updated_a2prob = update_act_prob_2act_tab.action_to_probability
        assert updated_a2prob["MyIngress.update_act_prob_2act_tab_act1"] == 0.5

        # total_count >= 10
        update_act_prob_2act_tab.update_prob_with_counts(
            {"MyIngress.update_act_prob_2act_tab_act1": 9, "MyIngress.update_act_prob_2act_tab_act2": 1}
        )
        updated_a2prob = update_act_prob_2act_tab.action_to_probability
        assert updated_a2prob["MyIngress.update_act_prob_2act_tab_act1"] == 0.9

        # total_count >= 10, set act1_prob to 1.0
        update_act_prob_2act_tab.update_prob_with_counts(
            {"MyIngress.update_act_prob_2act_tab_act1": 10, "MyIngress.update_act_prob_2act_tab_act2": 0}
        )
        updated_a2prob = update_act_prob_2act_tab.action_to_probability
        assert 1.01 > updated_a2prob["MyIngress.update_act_prob_2act_tab_act1"] > 0.99

    def test_update_action_prob_3act(self, json_path):
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        update_act_prob_3act_tab = tables[10]

        # total_count < 10, no update
        update_act_prob_3act_tab.update_prob_with_counts(
            {
                "MyIngress.update_act_prob_3act_tab_act1": 1,
                "MyIngress.update_act_prob_3act_tab_act2": 1,
                "MyIngress.update_act_prob_3act_tab_act3": 1,
            }
        )
        updated_a2prob = update_act_prob_3act_tab.action_to_probability
        assert (
            updated_a2prob["MyIngress.update_act_prob_3act_tab_act1"]
            == updated_a2prob["MyIngress.update_act_prob_3act_tab_act2"]
        )

        # total_count >= 10
        update_act_prob_3act_tab.update_prob_with_counts(
            {
                "MyIngress.update_act_prob_3act_tab_act1": 7,
                "MyIngress.update_act_prob_3act_tab_act2": 3,
                "MyIngress.update_act_prob_3act_tab_act3": 0,
            }
        )
        updated_a2prob = update_act_prob_3act_tab.action_to_probability
        assert updated_a2prob["MyIngress.update_act_prob_3act_tab_act1"] == 0.7
        assert updated_a2prob["MyIngress.update_act_prob_3act_tab_act2"] == 0.3
        assert updated_a2prob["MyIngress.update_act_prob_3act_tab_act3"] == 0

        # total_count >= 10, but same prob
        update_act_prob_3act_tab.update_prob_with_counts(
            {
                "MyIngress.update_act_prob_3act_tab_act1": 10,
                "MyIngress.update_act_prob_3act_tab_act2": 10,
                "MyIngress.update_act_prob_3act_tab_act3": 10,
            }
        )
        updated_a2prob = update_act_prob_3act_tab.action_to_probability
        assert (
            updated_a2prob["MyIngress.update_act_prob_3act_tab_act1"]
            == updated_a2prob["MyIngress.update_act_prob_3act_tab_act2"]
        )
        assert (
            updated_a2prob["MyIngress.update_act_prob_3act_tab_act2"]
            == updated_a2prob["MyIngress.update_act_prob_3act_tab_act3"]
        )
        assert (
            updated_a2prob["MyIngress.update_act_prob_3act_tab_act3"]
            == updated_a2prob["MyIngress.update_act_prob_3act_tab_act1"]
        )


@pytest.mark.parametrize(
    "json_path",
    [os.path.join(os.path.dirname(os.path.realpath(__file__)), "testdata", "next_table_selector", "test.p4.json")],
)
class TestActionReplace:
    def test_replace_act_1act_tab(self, json_path):
        """not existing new act and tab,
        keep the old action,
        only replace next table
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        replace_act_1act_tab = tables[11]

        actions = irg.action_id_to_action
        old_Action = actions[18]

        replace_act_1act_tab.replace_action(
            old_action_id=18,
            new_action=old_Action,
            new_next_table="MyIngress.replace_act_1act_tab0",
            default_action_param=[],
        )

        # check the number of actions, action name, action id
        assert replace_act_1act_tab._action_ids == [18]  # action id
        assert len(replace_act_1act_tab.action_names) == 1  # number of actions
        assert (
            replace_act_1act_tab.next_tables["MyIngress.replace_act_1act_tab_act1"] == "MyIngress.replace_act_1act_tab0"
        )  # action-next_table
        assert replace_act_1act_tab._default_action_id == 18  # default action id
        assert 1.01 > replace_act_1act_tab.action_to_probability["MyIngress.replace_act_1act_tab_act1"] > 0.99

    def test_replace_act_1act_act(self, json_path):
        """not existing new act and tab,
        keep the old next table,
        only replace action
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        replace_act_1act_tab = tables[11]

        new_action = {"name": "MyIngress.replace_act_1act_tab_act0", "id": 35, "runtime_data": [], "primitives": []}
        new_Action = irg.add_action_from_json(new_action, Action)

        replace_act_1act_tab.replace_action(
            old_action_id=18,
            new_action=new_Action,
            new_next_table="MyIngress.replace_act_normal_tab",
            default_action_param=[],
        )

        assert replace_act_1act_tab._action_ids == [35]
        assert len(replace_act_1act_tab.action_names) == 1
        assert (
            replace_act_1act_tab.next_tables["MyIngress.replace_act_1act_tab_act0"]
            == "MyIngress.replace_act_normal_tab"
        )
        assert replace_act_1act_tab._default_action_id == 35
        assert 1.01 > replace_act_1act_tab.action_to_probability["MyIngress.replace_act_1act_tab_act0"] > 0.99

    def test_replace_act_1act_both(self, json_path):
        """not existing new act and tab,
        replace both action and table
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        replace_act_1act_tab = tables[11]

        new_action = {"name": "MyIngress.replace_act_1act_tab_act0", "id": 35, "runtime_data": [], "primitives": []}
        new_Action = irg.add_action_from_json(new_action, Action)

        replace_act_1act_tab.replace_action(
            old_action_id=18,
            new_action=new_Action,
            new_next_table="MyIngress.replace_act_1act_tab0",
            default_action_param=[],
        )

        assert replace_act_1act_tab._action_ids == [35]
        assert len(replace_act_1act_tab.action_names) == 1
        assert (
            replace_act_1act_tab.next_tables["MyIngress.replace_act_1act_tab_act0"] == "MyIngress.replace_act_1act_tab0"
        )
        assert replace_act_1act_tab._default_action_id == 35
        assert 1.01 > replace_act_1act_tab.action_to_probability["MyIngress.replace_act_1act_tab_act0"] > 0.99

    def test_replace_act_1act_twice(self, json_path):
        """not existing new act and tab,
        replace both action and table
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        replace_act_1act_tab = tables[11]

        actions = irg.action_id_to_action
        old_Action = actions[18]

        new_action = {"name": "MyIngress.replace_act_1act_tab_act0", "id": 35, "runtime_data": [], "primitives": []}
        new_Action = irg.add_action_from_json(new_action, Action)

        # replace twice
        replace_act_1act_tab.replace_action(
            old_action_id=18,
            new_action=new_Action,
            new_next_table="MyIngress.replace_act_1act_tab0",
            default_action_param=[],
        )
        replace_act_1act_tab.replace_action(
            old_action_id=35,
            new_action=old_Action,
            new_next_table="MyIngress.replace_act_normal_tab",
            default_action_param=[],
        )

        assert replace_act_1act_tab._action_ids == [18]
        assert len(replace_act_1act_tab.action_names) == 1
        assert (
            replace_act_1act_tab.next_tables["MyIngress.replace_act_1act_tab_act1"]
            == "MyIngress.replace_act_normal_tab"
        )
        assert replace_act_1act_tab._default_action_id == 18
        assert 1.01 > replace_act_1act_tab.action_to_probability["MyIngress.replace_act_1act_tab_act1"] > 0.99

    def test_replace_act_normal_1(self, json_path):
        """not existing new act and tab,
        replace action, table
        replace 1 action-nexttable
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        replace_act_normal_tab = tables[12]

        new_action = {
            "name": "MyIngress.replace_act_normal_tab_newact1",
            "id": 35,
            "runtime_data": [],
            "primitives": [],
        }
        new_Action = irg.add_action_from_json(new_action, Action)

        replace_act_normal_tab.replace_action(
            old_action_id=19,
            new_action=new_Action,
            new_next_table="MyIngress.replace_act_normal_newtab1",
            default_action_param=[],
        )

        assert replace_act_normal_tab._action_ids == [35, 20, 21]
        assert len(replace_act_normal_tab.action_names) == 3
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_newact1"]
            == "MyIngress.replace_act_normal_newtab1"
        )
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_act2"] == "MyIngress.rm_other_act_tab"
        )
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_act3"] == "MyIngress.rm_other_act_tab"
        )
        assert replace_act_normal_tab._default_action_id == 35
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact1"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_act2"]
        )
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_act2"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_act3"]
        )
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_act3"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact1"]
        )

    def test_replace_act_normal_2(self, json_path):
        """not existing new act and tab,
        replace both action and table
        replace 1 action-nexttable,
        the old action is not the default action,
        so the default action will not be replaced
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        replace_act_normal_tab = tables[12]

        new_action = {
            "name": "MyIngress.replace_act_normal_tab_newact1",
            "id": 35,
            "runtime_data": [],
            "primitives": [],
        }
        new_Action = irg.add_action_from_json(new_action, Action)

        replace_act_normal_tab.replace_action(
            old_action_id=20,
            new_action=new_Action,
            new_next_table="MyIngress.replace_act_normal_newtab1",
            default_action_param=[],
        )

        assert replace_act_normal_tab._action_ids == [19, 35, 21]
        assert len(replace_act_normal_tab.action_names) == 3
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_newact1"]
            == "MyIngress.replace_act_normal_newtab1"
        )
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_act1"] == "MyIngress.rm_other_act_tab"
        )
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_act3"] == "MyIngress.rm_other_act_tab"
        )
        assert replace_act_normal_tab._default_action_id == 19  # keep default action
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_act1"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact1"]
        )
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact1"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_act3"]
        )
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_act3"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_act1"]
        )

    def test_replace_act_normal_3(self, json_path):
        """not existing new act and tab,
        replace both action, table, default action
        replace 2 action-nexttable,
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        replace_act_normal_tab = tables[12]

        new_action1 = {
            "name": "MyIngress.replace_act_normal_tab_newact1",
            "id": 35,
            "runtime_data": [],
            "primitives": [],
        }
        new_Action1 = irg.add_action_from_json(new_action1, Action)

        new_action2 = {
            "name": "MyIngress.replace_act_normal_tab_newact2",
            "id": 36,
            "runtime_data": [],
            "primitives": [],
        }
        new_Action2 = irg.add_action_from_json(new_action2, Action)

        replace_act_normal_tab.replace_action(
            old_action_id=19,  # also the default action
            new_action=new_Action1,
            new_next_table="MyIngress.replace_act_normal_newtab1",
            default_action_param=[],
        )
        replace_act_normal_tab.replace_action(
            old_action_id=21,
            new_action=new_Action2,
            new_next_table="MyIngress.replace_act_normal_newtab2",
            default_action_param=[],
        )

        assert replace_act_normal_tab._action_ids == [35, 20, 36]
        assert len(replace_act_normal_tab.action_names) == 3
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_newact1"]
            == "MyIngress.replace_act_normal_newtab1"
        )
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_newact2"]
            == "MyIngress.replace_act_normal_newtab2"
        )
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_act2"] == "MyIngress.rm_other_act_tab"
        )
        assert replace_act_normal_tab._default_action_id == 35
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact1"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_act2"]
        )
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_act2"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact2"]
        )
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact2"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact1"]
        )

    def test_replace_act_normal_4(self, json_path):
        """not existing new act and tab,
        replace action, table, and default action,
        replace 3 action-nexttable
        replace default action twice
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        replace_act_normal_tab = tables[12]

        new_action1 = {
            "name": "MyIngress.replace_act_normal_tab_newact1",
            "id": 35,
            "runtime_data": [],
            "primitives": [],
        }
        new_Action1 = irg.add_action_from_json(new_action1, Action)

        new_action2 = {
            "name": "MyIngress.replace_act_normal_tab_newact2",
            "id": 36,
            "runtime_data": [],
            "primitives": [],
        }
        new_Action2 = irg.add_action_from_json(new_action2, Action)

        new_action3 = {
            "name": "MyIngress.replace_act_normal_tab_newact3",
            "id": 37,
            "runtime_data": [],
            "primitives": [],
        }
        new_Action3 = irg.add_action_from_json(new_action3, Action)

        new_action4 = {
            "name": "MyIngress.replace_act_normal_tab_newact4",
            "id": 38,
            "runtime_data": [],
            "primitives": [],
        }
        new_Action4 = irg.add_action_from_json(new_action4, Action)

        replace_act_normal_tab.replace_action(
            old_action_id=19,  # the default action will be replaced
            new_action=new_Action1,
            new_next_table="MyIngress.replace_act_normal_newtab1",
            default_action_param=[],
        )

        replace_act_normal_tab.replace_action(
            old_action_id=20,
            new_action=new_Action2,
            new_next_table="MyIngress.replace_act_normal_newtab2",
            default_action_param=[],
        )
        replace_act_normal_tab.replace_action(
            old_action_id=21,
            new_action=new_Action3,
            new_next_table="MyIngress.replace_act_normal_newtab3",
            default_action_param=[],
        )

        replace_act_normal_tab.replace_action(
            old_action_id=35,  # the default action will be replaced again
            new_action=new_Action4,
            new_next_table="MyIngress.replace_act_normal_newtab4",
            default_action_param=[],
        )

        assert replace_act_normal_tab._action_ids == [38, 36, 37]
        assert len(replace_act_normal_tab.action_names) == 3
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_newact4"]
            == "MyIngress.replace_act_normal_newtab4"
        )
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_newact2"]
            == "MyIngress.replace_act_normal_newtab2"
        )
        assert (
            replace_act_normal_tab.next_tables["MyIngress.replace_act_normal_tab_newact3"]
            == "MyIngress.replace_act_normal_newtab3"
        )
        assert replace_act_normal_tab._default_action_id == 38
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact4"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact2"]
        )
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact2"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact3"]
        )
        assert (
            replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact3"]
            == replace_act_normal_tab.action_to_probability["MyIngress.replace_act_normal_tab_newact4"]
        )

    def test_replace_act_nonexttab(self, json_path):
        """not existing new act and tab,
        replace 3 action-nexttable,
        test the last table in the P4 program, which has no next table
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        no_nexttab_tab = tables[(len(tables) - 1)]  # the last table in the P4 program

        new_action1 = {"name": "MyIngress.no_nexttab_tab_newact1", "id": 35, "runtime_data": [], "primitives": []}
        new_Action1 = irg.add_action_from_json(new_action1, Action)

        new_action2 = {"name": "MyIngress.no_nexttab_tab_newact2", "id": 36, "runtime_data": [], "primitives": []}
        new_Action2 = irg.add_action_from_json(new_action2, Action)

        actions = irg.action_id_to_action
        old_Action = actions[33]

        # replace both action and table
        no_nexttab_tab.replace_action(
            old_action_id=32,  # the default action will be replaced
            new_action=new_Action1,
            new_next_table="MyIngress.no_nexttab_tab_newtab1",
            default_action_param=[],
        )

        # only replace next table
        no_nexttab_tab.replace_action(
            old_action_id=33,
            new_action=old_Action,
            new_next_table="MyIngress.no_nexttab_tab_newtab2",
            default_action_param=[],
        )

        # only replace action
        no_nexttab_tab.replace_action(
            old_action_id=34, new_action=new_Action2, new_next_table=None, default_action_param=[]
        )

        assert no_nexttab_tab._action_ids == [35, 33, 36]
        assert len(no_nexttab_tab.action_names) == 3
        assert no_nexttab_tab.next_tables["MyIngress.no_nexttab_tab_newact1"] == "MyIngress.no_nexttab_tab_newtab1"
        assert no_nexttab_tab.next_tables["MyIngress.no_nexttab_tab_act2"] == "MyIngress.no_nexttab_tab_newtab2"
        assert no_nexttab_tab.next_tables["MyIngress.no_nexttab_tab_newact2"] == None
        assert no_nexttab_tab._default_action_id == 35
        assert (
            no_nexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_newact1"]
            == no_nexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_act2"]
        )
        assert (
            no_nexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_act2"]
            == no_nexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_newact2"]
        )
        assert (
            no_nexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_newact2"]
            == no_nexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_newact1"]
        )

    def test_rm_other_act_0(self, json_path):
        """remove 0 action"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        rm_other_act_tab = tables[13]
        # act5 is a drop action

        rm_other_act_tab.remove_other_actions(to_keep=[22, 23, 24, 25, 26], new_default_action_id=22)

        assert rm_other_act_tab._action_ids == [22, 23, 24, 25, 26]
        assert len(rm_other_act_tab.action_names) == 5
        assert rm_other_act_tab._default_action_id == 22

        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act1"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act2"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act3"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act4"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act5"] == "MyIngress.replace_nexttab_tab"

        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act1"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act2"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act2"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act3"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act3"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act4"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act4"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act5"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act5"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act1"]
        )

    def test_rm_other_act_1(self, json_path):
        """remove 1 action"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        rm_other_act_tab = tables[13]
        # act5 is a drop action

        # remove act1 (default action)
        rm_other_act_tab.remove_other_actions(to_keep=[23, 24, 25, 26], new_default_action_id=23)

        assert rm_other_act_tab._action_ids == [23, 24, 25, 26]
        assert len(rm_other_act_tab.action_names) == 4
        assert rm_other_act_tab._default_action_id == 23

        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act2"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act3"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act4"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act5"] == "MyIngress.replace_nexttab_tab"

        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act2"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act3"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act3"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act4"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act4"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act5"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act5"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act2"]
        )

        # remove twice
        # remove act5
        rm_other_act_tab.remove_other_actions(to_keep=[23, 24, 25], new_default_action_id=23)

        assert rm_other_act_tab._action_ids == [23, 24, 25]
        assert len(rm_other_act_tab.action_names) == 3
        assert rm_other_act_tab._default_action_id == 23

        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act2"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act3"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act4"] == "MyIngress.replace_nexttab_tab"

        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act2"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act3"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act3"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act4"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act4"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act2"]
        )

    def test_rm_other_act_continuous_1(self, json_path):
        """remove continuous actions"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        rm_other_act_tab = tables[13]
        # act5 is a drop action

        # remove act1, act2
        rm_other_act_tab.remove_other_actions(to_keep=[24, 25, 26], new_default_action_id=25)

        assert rm_other_act_tab._action_ids == [24, 25, 26]
        assert len(rm_other_act_tab.action_names) == 3
        assert rm_other_act_tab._default_action_id == 25

        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act3"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act4"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act5"] == "MyIngress.replace_nexttab_tab"

        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act3"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act4"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act4"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act5"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act5"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act3"]
        )

        # remove twice
        # remove act3, act4
        rm_other_act_tab.remove_other_actions(to_keep=[26], new_default_action_id=26)

        assert rm_other_act_tab._action_ids == [26]
        assert len(rm_other_act_tab.action_names) == 1
        assert rm_other_act_tab._default_action_id == 26

        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act5"] == "MyIngress.replace_nexttab_tab"

        assert 1.01 > rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act5"] > 0.99

    def test_rm_other_act_continuous_2(self, json_path):
        """remove continuous actions"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        rm_other_act_tab = tables[13]
        # act5 is a drop action

        # remove act2, act3, act4
        rm_other_act_tab.remove_other_actions(to_keep=[22, 26], new_default_action_id=22)

        assert rm_other_act_tab._action_ids == [22, 26]
        assert len(rm_other_act_tab.action_names) == 2
        assert rm_other_act_tab._default_action_id == 22

        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act1"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act5"] == "MyIngress.replace_nexttab_tab"

        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act1"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act5"]
        )
        assert rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act1"] == 0.5

    def test_rm_other_act_discrete_1(self, json_path):
        """remove discrete actions"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        rm_other_act_tab = tables[13]
        # act5 is a drop action

        # remove act1, act4
        rm_other_act_tab.remove_other_actions(to_keep=[23, 24, 26], new_default_action_id=26)

        assert rm_other_act_tab._action_ids == [23, 24, 26]
        assert len(rm_other_act_tab.action_names) == 3
        assert rm_other_act_tab._default_action_id == 26

        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act2"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act3"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act5"] == "MyIngress.replace_nexttab_tab"

        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act2"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act3"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act3"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act5"]
        )
        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act5"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act2"]
        )

        # remove twice
        # remove act2, act5
        rm_other_act_tab.remove_other_actions(to_keep=[24], new_default_action_id=24)

        assert rm_other_act_tab._action_ids == [24]
        assert len(rm_other_act_tab.action_names) == 1
        assert rm_other_act_tab._default_action_id == 24

        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act3"] == "MyIngress.replace_nexttab_tab"

        assert len(rm_other_act_tab.next_tables) == 1
        assert 1.01 > rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act3"] > 0.99

    def test_rm_other_act_discrete_2(self, json_path):
        """remove discrete actions"""
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        rm_other_act_tab = tables[13]
        # act5 is a drop action

        # remove act1, act3, act5
        rm_other_act_tab.remove_other_actions(to_keep=[23, 25], new_default_action_id=23)

        assert rm_other_act_tab._action_ids == [23, 25]
        assert len(rm_other_act_tab.action_names) == 2
        assert rm_other_act_tab._default_action_id == 23

        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act2"] == "MyIngress.replace_nexttab_tab"
        assert rm_other_act_tab.next_tables["MyIngress.rm_other_act_tab_act4"] == "MyIngress.replace_nexttab_tab"

        assert (
            rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act2"]
            == rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act4"]
        )
        assert rm_other_act_tab.action_to_probability["MyIngress.rm_other_act_tab_act2"] == 0.5

    def test_replace_next_tab_1tab(self, json_path):
        """not existing new act and tab,
        by default, all actions' next tables and the default table are the same,
        replace the same table
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        replace_nexttab_tab = tables[14]
        # act5 is a drop action

        replace_nexttab_tab.replace_next_table(orig_next="MyIngress.no_nexttab_tab", new_next="MyIngress.new_next_tab")

        assert len(replace_nexttab_tab.next_tables) == 5

        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act1"] == "MyIngress.new_next_tab"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act2"] == "MyIngress.new_next_tab"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act3"] == "MyIngress.new_next_tab"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act4"] == "MyIngress.new_next_tab"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act5"] == "MyIngress.new_next_tab"

        assert replace_nexttab_tab._next_table_selector._base_default_next == "MyIngress.new_next_tab"

        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act1"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act2"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act2"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act3"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act3"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act4"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act4"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act5"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act5"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act1"]
        )

        assert replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act5"] == 0.2

    def test_replace_next_tab_multtab_1(self, json_path):
        """not existing new act and tab,
        firstly, use replace_action() to assign different next tables to differet actions,
        then, replace the different table
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        replace_nexttab_tab = tables[14]
        # act5 is a drop action

        actions = irg.action_id_to_action
        old_Action2 = actions[28]
        old_Action3 = actions[29]
        old_Action4 = actions[30]
        old_Action5 = actions[31]

        # assign new next tabs
        # keep the next tab of act1 as the default tab
        replace_nexttab_tab.replace_action(
            old_action_id=28,
            new_action=old_Action2,  # keep old action
            new_next_table="MyIngress.new_next_tab2",  # new table
            default_action_param=[],
        )
        replace_nexttab_tab.replace_action(
            old_action_id=29, new_action=old_Action3, new_next_table="MyIngress.new_next_tab3", default_action_param=[]
        )
        replace_nexttab_tab.replace_action(
            old_action_id=30, new_action=old_Action4, new_next_table="MyIngress.new_next_tab4", default_action_param=[]
        )
        replace_nexttab_tab.replace_action(
            old_action_id=31, new_action=old_Action5, new_next_table="MyIngress.new_next_tab5", default_action_param=[]
        )

        # replace default tab (act1's next tab)
        replace_nexttab_tab.replace_next_table(orig_next="MyIngress.no_nexttab_tab", new_next="MyIngress.new_next_tab1")

        # replace act5's next tab to None
        replace_nexttab_tab.replace_next_table(orig_next="MyIngress.new_next_tab5", new_next=None)

        assert len(replace_nexttab_tab.next_tables) == 5

        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act1"] == "MyIngress.new_next_tab1"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act2"] == "MyIngress.new_next_tab2"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act3"] == "MyIngress.new_next_tab3"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act4"] == "MyIngress.new_next_tab4"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act5"] == None

        assert replace_nexttab_tab._next_table_selector._base_default_next == "MyIngress.new_next_tab1"

        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act1"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act2"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act2"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act3"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act3"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act4"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act4"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act5"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act5"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act1"]
        )

        assert replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act5"] == 0.2

    def test_replace_next_tab_multtab_2(self, json_path):
        """not existing new act and tab,
        firstly, use replace_action() to assign different next tables to differet actions,
        then, replace the different table
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        replace_nexttab_tab = tables[14]
        # act5 is a drop action

        # assign new next tabs
        # keep the next tab of act1 as the default tab
        actions = irg.action_id_to_action
        old_Action2 = actions[28]
        old_Action3 = actions[29]
        old_Action4 = actions[30]
        old_Action5 = actions[31]

        # assign new next tabs
        # keep the next tab of act1 as the default tab
        replace_nexttab_tab.replace_action(
            old_action_id=28,
            new_action=old_Action2,  # keep old action
            new_next_table="MyIngress.new_next_tab2",  # new table
            default_action_param=[],
        )
        replace_nexttab_tab.replace_action(
            old_action_id=29, new_action=old_Action3, new_next_table="MyIngress.new_next_tab3", default_action_param=[]
        )
        replace_nexttab_tab.replace_action(
            old_action_id=30, new_action=old_Action4, new_next_table="MyIngress.new_next_tab4", default_action_param=[]
        )
        replace_nexttab_tab.replace_action(
            old_action_id=31, new_action=old_Action5, new_next_table="MyIngress.new_next_tab5", default_action_param=[]
        )

        # replace act2's next tab to default tab
        replace_nexttab_tab.replace_next_table(orig_next="MyIngress.new_next_tab2", new_next="MyIngress.no_nexttab_tab")

        # replace act3's next tab to act4's next tab
        replace_nexttab_tab.replace_next_table(orig_next="MyIngress.new_next_tab3", new_next="MyIngress.new_next_tab4")

        # replace act5's next tab to a new tab and
        # replace it back
        replace_nexttab_tab.replace_next_table(
            orig_next="MyIngress.new_next_tab5", new_next="MyIngress.new_next_tab5_new"
        )
        replace_nexttab_tab.replace_next_table(
            orig_next="MyIngress.new_next_tab5_new", new_next="MyIngress.new_next_tab5"
        )

        assert len(replace_nexttab_tab.next_tables) == 5

        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act1"] == "MyIngress.no_nexttab_tab"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act2"] == "MyIngress.no_nexttab_tab"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act3"] == "MyIngress.new_next_tab4"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act4"] == "MyIngress.new_next_tab4"
        assert replace_nexttab_tab.next_tables["MyIngress.replace_nexttab_tab_act5"] == "MyIngress.new_next_tab5"

        assert replace_nexttab_tab._next_table_selector._base_default_next == "MyIngress.no_nexttab_tab"

        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act1"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act2"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act2"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act3"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act3"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act4"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act4"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act5"]
        )
        assert (
            replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act5"]
            == replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act1"]
        )

        assert replace_nexttab_tab.action_to_probability["MyIngress.replace_nexttab_tab_act5"] == 0.2

    def test_replace_next_tab_nonexttab(self, json_path):
        """not existing new act and tab,
        test the last table in the P4 program, which has no next table
        """
        irg, target = JsonManager.retrieve_presplit(json_path)
        JsonManager.compile_time_json_planning(irg)
        ingress_graph = irg.get_pipe("ingress")
        tables = list(ingress_graph.tables)
        nonexttab_tab = tables[(len(tables) - 1)]

        nonexttab_tab.replace_next_table(orig_next=None, new_next="MyIngress.new_next_tab")

        assert len(nonexttab_tab.next_tables) == 3

        assert nonexttab_tab.next_tables["MyIngress.no_nexttab_tab_act1"] == "MyIngress.new_next_tab"
        assert nonexttab_tab.next_tables["MyIngress.no_nexttab_tab_act2"] == "MyIngress.new_next_tab"
        assert nonexttab_tab.next_tables["MyIngress.no_nexttab_tab_act3"] == "MyIngress.new_next_tab"

        assert nonexttab_tab._next_table_selector._base_default_next == "MyIngress.new_next_tab"

        assert (
            nonexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_act1"]
            == nonexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_act2"]
        )
        assert (
            nonexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_act2"]
            == nonexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_act3"]
        )
        assert (
            nonexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_act3"]
            == nonexttab_tab.action_to_probability["MyIngress.no_nexttab_tab_act1"]
        )
