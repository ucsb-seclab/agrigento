#!/usr/bin/env python

import sys
import os

from time import time

from core.flows_analyzer import whitelist_analysis
from core.convergence import convergence_analysis

MAX_NUMBER_RUNS = 15
CONVERGENCE_THRESHOLD = 3

def main():
    app_name = sys.argv[1]
    fdir = sys.argv[2]
    cdir = sys.argv[3]
    wtdir = sys.argv[4]
    if len(sys.argv) > 5:
        global CONVERGENCE_THRESHOLD
        CONVERGENCE_THRESHOLD = int(sys.argv[5])
    if len(sys.argv) > 6:
        global MAX_NUMBER_RUNS
        MAX_NUMBER_RUNS = int(sys.argv[6])

    n_runs = 2
    converged = 0

    start_time = time()
    while n_runs < MAX_NUMBER_RUNS:
        results = convergence_analysis(app_name, n_runs, fdir=fdir, cdir=cdir)
        if not results:
            converged += 1
        else:
            converged = 0

        if converged >= CONVERGENCE_THRESHOLD:
            break
        n_runs += 1

    whitelist_analysis(app_name, num_runs=n_runs, fdir=fdir, cdir=cdir, wtdir=wtdir)
    end_time = time()
    output_dir = os.path.join(wtdir, app_name)
    out_file = open(os.path.join(output_dir, 'runs-threshold'), 'w')
    out_file.write(str(n_runs) + '\n')
    out_file.close()

    elapsed_time = end_time - start_time
    print '[SIMULATE-CONVERGENCE] Completed! Elapsed time: {0} seconds. #Runs: {1}'.format(elapsed_time, n_runs)


if __name__ == '__main__':
    main()
