import itertools
import pdb
import signal
import time

import angr
import claripy
import os
import sys
from termcolor import colored
import traceback
import code


def run_symexe_debug(path, argv_size=2):
    sym_argv = claripy.BVS('sym_argv', argv_size * 8)

    try:
        p = angr.Project(path, load_options={"auto_load_libs": True})
    except:
        print(colored('Invalid path: \"' + path + '\"', 'red'))
        return None

    state = p.factory.entry_state(args=[p.filename, sym_argv])
    pg = p.factory.simgr(state)
    pg.use_technique(angr.exploration_techniques.DFS())

    for byte in sym_argv.chop(8):
        state.add_constraints(byte != '\x00')  # null
        state.add_constraints(byte >= ' ')  # '\x20'
        state.add_constraints(byte <= '~')  # '\x7e'

    def killmyself():
        os.system('kill %d' % os.getpid())

    def sigint_handler(signum, frame):
        # killmyself()
        print('Stopping Execution for Debug. If you want to kill the programm issue: killmyself()')
        if not "IPython" in sys.modules:
            import IPython
            IPython.embed()

    def handler(signum, frame):
        print(traceback.format_stack())
        signal.alarm(1)
        # pdb.set_trace()

    # signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(1)
    pg.run()
    signal.alarm(0)
    print("analysis debug ended")


def run_symexe_by_step(path, argv_size=2):
    sym_argv = claripy.BVS('sym_argv', argv_size * 8)

    try:
        p = angr.Project(path, load_options={"auto_load_libs": True})
    except:
        print(colored('Invalid path: \"' + path + '\"', 'red'))
        return None

    state = p.factory.entry_state(args=[p.filename, sym_argv])
    pg = p.factory.simgr(state)
    pg.use_technique(angr.exploration_techniques.DFS())

    def handler(signum, frame):
        # signal.alarm(1)
        pdb.set_trace()

    # signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGALRM, handler)
    # signal.alarm(60)
    for _ in (itertools.count()):
        if not pg.complete() and pg._stashes['active']:
            start_time = time.time()
            pg.step(stash='active')
            end_time = time.time()
            time_delta = end_time - start_time
            try:
                print(pg.active[0].ip, time_delta)
            except:
                print(_)
            continue
        break
        # if len(pg.active) == 0:
        #     break
    # signal.alarm(0)
    print("analysis debug ended")
