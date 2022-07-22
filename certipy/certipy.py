import sys
import argparse
from utils.CertificateCloner import CertificateCloner


def main(args: argparse.Namespace):
    c = CertificateCloner(args)
    c.clone()
    c.dump()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub_parser = parser.add_subparsers(help="List of available certificate operations.", dest="module")
    CertificateCloner.get_add_argparse_arguments(sub_parser)
    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    main(args)
