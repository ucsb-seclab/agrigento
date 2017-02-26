#!/usr/bin/env python

import sys

from core.flows_analyzer import whitelist_analysis
from config.values import data_default


def main():
    app_name = sys.argv[1]
    fields = data_default.keys()
    fields.append('all')

    if len(sys.argv) == 2:
        whitelist_analysis(app_name, field=fields)
    elif len(sys.argv) == 3:
        whitelist_analysis(app_name, num_runs=int(sys.argv[2]), field=fields)
    elif len(sys.argv) == 5:
        whitelist_analysis(app_name, fdir=sys.argv[2], cdir=sys.argv[3], wtdir=sys.argv[4], field=fields)
    elif len(sys.argv) == 6:
        whitelist_analysis(app_name, num_runs=int(sys.argv[2]), fdir=sys.argv[3], cdir=sys.argv[4], wtdir=sys.argv[5], field=fields)


if __name__ == '__main__':
    main()
