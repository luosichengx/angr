import fcntl
import json
import configparser
import os

cf = configparser.ConfigParser()
cf.read("./config.ini")
output_path = cf.get("Path", "output")


def write_constraints(path, dd, time_delta, res):
    con = []
    for c in dd.solver.constraints:
        con.append(str(c))
    # data = {"file name": path, "constraints": con, "time": str(time_delta) + 's'}
    data = {"file name": path, "constraints": con, "time": str(time_delta) + 's', "result": str(res)}
    # data = {"file name":path, "constraints":con, "time":str(time_delta) + 's', "time100":str(time_delta100) + 's'}
    d = json.dumps(data, indent=4, separators=(',', ': '))
    with open(output_path, 'a') as f:
        f.write(d + ",\n")