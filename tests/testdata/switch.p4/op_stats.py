from collections import Counter
import json


def stat_all_op():
    with open("switch.json", "r") as f:
        p4c_ir = f.readlines()
        ops = []
        counter = 0
        for line in p4c_ir:
            if '"op"' in line:
                counter += 1
                ops.append(line.strip().rstrip())
        print(counter)
        for k, v in Counter(ops).items():
            print("{:<8}{:<8}".format(v, k))


def stat_first_op():
    with open("switch.json", "r") as f:
        p4c_ir = json.load(f)

        ops = []
        counter = 0

        actions = p4c_ir["actions"]

        for a in actions:
            primitives = a["primitives"]
            for prim in primitives:
                ops.append(prim["op"])
                counter += 1

        print(counter)
        for k, v in Counter(ops).items():
            print("{:<8}{:<8}".format(v, k))


if __name__ == "__main__":
    stat_first_op()
