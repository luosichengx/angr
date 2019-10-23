import json
import signal
import threading

import angr
import claripy
import os
import sys
import time
import argparse
import logging
import multiprocessing as mp
from termcolor import colored
import configparser
import os

cf = configparser.ConfigParser()
cf.read("./confign.ini")
from write_cn import write_constraints
from run_debug import run_symexe_debug, run_symexe_by_step


def run_symexe(path, argv_size=8, show_bytes=True, show_model=False, withtime=True):
    logger.info('===========================================')
    logger.info('Analysing ' + path)
    sym_argv = claripy.BVS('sym_argv', argv_size * 8)
    sym_argv2 = claripy.BVS('sym_argv', 2 * 8)
    sym_argv3 = claripy.BVS('sym_argv', 2 * 8)

    try:
        load_lib_bool = cf.getboolean("Angr", "lib")
        p = angr.Project(path, load_options={"auto_load_libs": load_lib_bool})
    except:
        print(colored('Invalid path: \"' + path + '\"', 'red'))
        logger.error('invalid path or load lib failed')
        return None
    # cfg = p.analyses.CFGFast(normalize=True)
    state = p.factory.entry_state(args=[p.filename, sym_argv])
    # state = p.factory.entry_state(args=[p.filename, sym_argv], add_options={angr.options.LAZY_SOLVES})
    pg = p.factory.simgr(state)
    # pg.use_technique(angr.exploration_techniques.DFS())
    # pg.use_technique(angr.exploration_techniques.Veritesting())
    # pg.use_technique(angr.exploration_techniques.LengthLimiter(max_length=2000))
    # pg.use_technique(angr.exploration_techniques.LoopSeer(bound=10))
    # pg.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=10))
    for byte in sym_argv.chop(8):
        state.add_constraints(byte != '\x00')  # null
        state.add_constraints(byte >= ' ')  # '\x20'
        state.add_constraints(byte <= '~')  # '\x7e'

    def handler(signum, frame):
        signal.alarm(5)
        raise TimeoutError

    def killmyself():
        os.system('kill %d' % os.getpid())

    def sigint_handler(signum, frame):
        killmyself()
        if not "IPython" in sys.modules:
            import IPython
            IPython.embed()

    tel = cf.getint("Time", "explore")
    tsl = cf.getint("Time", "solve")
    try:
        if withtime:
            # signal.signal(signal.SIGINT, sigint_handler)
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(tel)
            start_time = time.time()
            pg.run()
            end_time = time.time()
            time_delta = end_time - start_time
            print(time_delta)
            signal.alarm(0)
        else:
            pg.run()
    except TimeoutError:
        logger.warning('Analysing time out')
        signal.alarm(0)
    # pg.run()

    print(colored('[*] Paths found: ' + str(len(pg.deadended)), 'white'))

    pp = mp.Pool()
    results = []

    for dd in pg.deadended:
        # start_time = time.time()
        # res = dd.solver.eval(sym_argv, cast_to=bytes)
        # end_time = time.time()
        # time_delta = end_time - start_time

        try:
            if withtime:
                signal.signal(signal.SIGALRM, handler)
                signal.alarm(tsl)
            start_time = time.time()
            res = dd.solver.eval(sym_argv, cast_to=bytes)
            end_time = time.time()
            if withtime:
                signal.alarm(0)
            time_delta = end_time - start_time
        except Exception:
            print("5s time out")
            logger.warning('Solving time out')
            time_delta = "5s time out"
            res = None
        results.append(res)
        print(res)
        if show_bytes:
            print(colored(b'[+] New Input: ' + res + b' |', 'green'))
            if show_model:
                print(colored(str(dd.solver.constraints), 'yellow'))
        else:
            print(colored('[+] New Input: ' + res, 'green'))
        print(len(dd.solver.constraints))
        pp.apply_async(write_constraints, args=(path, dd, time_delta, res))

        # extract to the function to use multiprocessing
        #
        # con = []
        # for c in dd.solver.constraints:
        #     con.append(str(c))
        # data = {"file name": path, "constraints": con, "time": str(time_delta) + 's'}
        # d = json.dumps(data, indent=4, separators=(',', ': '))
        # with open(output_path, 'a') as f:
        #     f.write(d + ",\n")

    if len(pg.deadended) == 0:
        logger.warning("no path found")
    else:
        logger.info(str(len(pg.deadended)) + " path found")
    pp.close()

    def write_handler(signum, frame):
        pp.terminate()

    signal.signal(signal.SIGALRM, write_handler)
    signal.alarm(60)
    pp.join()
    signal.alarm(0)
    errored = False
    for err in pg.errored:
        print(colored('[-] Error: ' + repr(err), 'red'))
        with open('errors.txt', 'a') as f:
            f.write(path + repr(err) + '\n')
        errored = True
    return results, errored


def conf_para(args):
    print(colored('[*] Analysing...', 'cyan'))
    try:
        print(colored(bin_path, 'cyan'))
        input_length = args.length

        if input_length is None:
            input_length = cf.getint("Symvar", "length")

        if args.debug:
            run_symexe_debug(bin_path,input_length)
        elif args.step:
            run_symexe_by_step(bin_path, input_length)
        else:
            results, errored = run_symexe(bin_path, input_length, show_model=args.constraints, withtime=args.time)
        print(colored('[*] Analysis completed\n', 'green'))
    except:
        print(colored('[*] Analysis failed\n', 'red'))
        logger.error('Analysing failed.')


if __name__ == '__main__':
    print('\n')
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dir", help="directory of data")
    parser.add_argument("-c", "--constraints", help="Show generated model", action="store_true")
    parser.add_argument("-C", "--compile", type=int, help="Compile from source, if C > 0, -O option will be used")
    parser.add_argument("-l", "--length", type=int, help="Stdin size")
    parser.add_argument("-r", "--run_program", help="Run program after analysis", action="store_true")
    parser.add_argument("-s", "--summary", type=int, help="Display summary information")
    parser.add_argument("-e", "--expected", type=int, help="Expected amount of results")
    parser.add_argument("-f", "--file_path", type=str, help="Binary path")
    parser.add_argument("-t", "--time", help="without time constraint", action="store_false")
    parser.add_argument("-de", "--debug", help="ctrl+c to debug the progress", action="store_true")
    parser.add_argument("-st", "--step", help="run the program by steps", action="store_true")
    args = parser.parse_args()

    log_path = cf.get("Path", "log")
    logger = logging.getLogger(__name__)
    logger.setLevel(level=logging.INFO)
    handler = logging.FileHandler(log_path, mode='w')
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger_angr = logging.getLogger('angr')
    logger_angr.setLevel(logging.ERROR)
    console = logging.StreamHandler()
    console.setLevel(logging.ERROR)

    logger.addHandler(handler)
    # logger.addHandler(console)
    output_path = cf.get("Path", "output")
    with open(output_path, 'w') as f:
        f.write("[\n")
    with open("stop.json", 'r') as f:
        jsondata = f.read()
    stoplist = json.loads(jsondata)["stoplist"]
    if args.dir is not None:
        dirpath = args.dir
        for root, dirs, files in os.walk(dirpath):
            print(root)
            print(files)
            for file in files:
                # if not os.access(file,os.X_OK):
                #     continue
                if file in stoplist:
                    continue
                if ".c" in file:

                    print(colored('[*] Compiling...', 'cyan'))
                    bin_dir, filename = root, file
                    bin_path = os.path.join(filename.split(".")[0], ".out")
                    if ".cpp" in file:
                        cmd = ' '.join(['g++ -o', os.path.join(bin_dir, bin_path),
                                        '-O1', os.path.join(bin_dir, filename)])
                    else:
                        cmd = ' '.join(['gcc -o', os.path.join(bin_dir, bin_path),
                                        '-O1', os.path.join(bin_dir, filename)])
                    print(cmd)
                    os.system(cmd)
                    print(colored('[*] Compile completed\n', 'green'))
                    bin_path = os.path.join(bin_dir, bin_path)
                else:
                    bin_path = os.path.join(root, file)

                conf_para(args)

    if args.file_path is not None:

        src_path = args.file_path
        if src_path in stoplist:
            pass
        elif ".c" in src_path:
            bin_path = src_path.split(".")[0] + '.out'
            print(colored('[*] Compiling...', 'cyan'))

            cmd = ' '.join(['gcc -o', bin_path, '-O1', src_path])

            print(cmd)
            os.system(cmd)
            print(colored('[*] Compile completed\n', 'green'))
        else:
            bin_path = src_path
        conf_para(args)

    try:
        with open(output_path, 'ab') as f:
            f.seek(-2, os.SEEK_END)
            f.truncate()
    except:
        pass
    with open(output_path, 'a') as f:
        f.write("\n]")
    print("all program ran")
