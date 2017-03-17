import argparse

def main():
	parser = argparse.ArgumentParser(desciption='This is a simple proxy http server')

	parser.add_argument('-v', '--version', default='version', help='Prints out version')
    parser.add_argument('-p', '--port', default='8899', help='Default: 8899')
    parser.add_argument('-n', '--numworker', default='10', help='The number of workers in the thread pool')
    parser.add_argument('-t', '--timeout', default='-1', help='Default: -1, Infinite')
    parser.add_argument('-l', '--log', default='INFO', help='DEBUG, INFO, WARNING, ERROR, CRITICAL')
    args = parser.parse_args()
    
if __name__ == "__main__":
    main()