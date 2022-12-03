import enum
import argparse
from utils.core import CertificateBase


class DumpType(enum.Enum):
    raw = enum.auto()
    pkcs12 = enum.auto()
    pkcs12_all = enum.auto()


class CertificateDownloader(CertificateBase):
    """
    This class queries certificates from a TLS service
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._tls_services = []
        for item in self._args.service:
            tmp = item.split(":")
            if len(tmp) == 1:
                raise ValueError("Invalid service format. Expected format is: HOSTNAME:PORT")
            host_name = ":".join(tmp[:-1])
            port = tmp[-1]
            if not port.isnumeric():
                raise ValueError("Provided port ({}) is not a number.".format(host_name, port))
            self._tls_services.append((host_name, int(port)))

    @staticmethod
    def get_add_argparse_arguments(sub_parser: argparse._SubParsersAction):
        """
        This method adds the class specific command line arguments.
        """
        parser = sub_parser.add_parser('query', help='This module queries certificates from a TLS service.')
        parser.add_argument('service',
                            type=str,
                            nargs="+",
                            help="""TLS service in the format of HOSTNAME:PORT from where the TLS services that
shall be cloned are obtained.""")
        parser.add_argument('-o', '--output',
                            type=str,
                            required=True,
                            help="Specifies the output file where the downloaded certificates are stored.")

    def download(self):
        """
        This method iterates through all TLS services and connects to them to download the TLS certificates.
        chain.
        :return:
        """
        with open(self._args.output, "w") as file:
            for host_name, port in self._tls_services:
                for item in self.get_certs_from_service(host_name, port):
                    file.write(item)
