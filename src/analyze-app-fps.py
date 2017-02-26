import sys

from emulator.fp_analysis import FalsePositivesAnalysis

RANDOMNESS = False

def main():
    # params: device_name, APK_path
    fpa = FalsePositivesAnalysis(sys.argv[1], sys.argv[2], randomness=RANDOMNESS)
    fpa.start_analysis()


if __name__ == '__main__':
    main()
