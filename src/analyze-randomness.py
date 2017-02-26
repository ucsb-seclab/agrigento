#!/usr/bin/env python

import sys

from core.randomness_analyzer import randomness_analysis


def main():
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print 'Use analyze-randomness.py <app_name> [<num_runs>]'
        exit()

    app_name = sys.argv[1]
    if len(sys.argv) == 2:
        randomness_analysis(app_name)
    elif len(sys.argv) == 3:
        randomness_analysis(app_name, num_runs=int(sys.argv[2]))


if __name__ == '__main__':
    main()
