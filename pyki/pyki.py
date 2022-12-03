#!/usr/bin/env python3

import sys
import argparse
from utils import CertificateCloner
from utils import CertificatePrinter
from utils import CertificateDownloader


def main(args: argparse.Namespace):
    if args.module == "print":
        c = CertificatePrinter(args=args)
        c.print()
    elif args.module == "clone":
        c = CertificateCloner(args=args)
        c.clone()
        c.dump()
    elif args.module == "query":
        c = CertificateDownloader(args=args)
        c.download()
    else:
        raise NotImplementedError("Case not implemented.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub_parser = parser.add_subparsers(help="List of available certificate operations.", dest="module")
    CertificateCloner.get_add_argparse_arguments(sub_parser)
    CertificatePrinter.get_add_argparse_arguments(sub_parser)
    CertificateDownloader.get_add_argparse_arguments(sub_parser)
    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)

    main(args)
