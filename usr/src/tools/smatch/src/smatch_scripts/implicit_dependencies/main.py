import argparse
import sys

from constants import (
    IMPL_DEP_FILE_STR,
    OUTPUT_FILE_STR,
)
from parser import Parser

def main():
    arg_parser = argparse.ArgumentParser(
        description="Control module for tracking implicit dependencies"
    )
    arg_parser.add_argument(
        "-f", "--file", default=IMPL_DEP_FILE_STR,
        help="path to kernel.implicit_dependencies",
    )
    arg_parser.add_argument(
        "-o", "--output", default=OUTPUT_FILE_STR,
        help="where to output info",
    )
    arg_parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="if verbose, we list what fields are responsible for the dependency"
    )
    arg_parser.add_argument(
        "-p", "--pretty", action="store_true",
        help="print implicit dependencies in pretty format"
    )
    args = arg_parser.parse_args()

    p = Parser(args.file, output_file_str=args.output, verbose=args.verbose, pretty=args.pretty)
    p.parse()
    p.write()
    p.close()


if __name__ == "__main__":
    sys.exit(main())
