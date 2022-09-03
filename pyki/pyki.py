import sys
import argparse
from utils.CertificateCloner import CertificateCloner
from utils.CertificatePrinter import CertificatePrinter


def main(args: argparse.Namespace):

    if args.module == "print":
        c = CertificatePrinter(args=args)
        c.print()
    elif args.module == "clone":
        c = CertificateCloner(args=args)
        c.clone()
        c.dump()
    else:
        raise NotImplementedError("Case not implemented.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub_parser = parser.add_subparsers(help="List of available certificate operations.", dest="module")
    CertificateCloner.get_add_argparse_arguments(sub_parser)
    CertificatePrinter.get_add_argparse_arguments(sub_parser)
    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    main(args)
