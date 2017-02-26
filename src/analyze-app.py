import sys

from emulator.dynamic_analysis import DynamicAnalysis


def main():
	if len(sys.argv) != 3:
        print 'Use: python analyze-app.py <device_name> <apk_path>'
        exit()
	# params: device_name, APK_path
	da = DynamicAnalysis(sys.argv[1], sys.argv[2])
	da.start_analysis()


if __name__ == '__main__':
	main()