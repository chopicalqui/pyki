import re
import os
import argparse
from OpenSSL import crypto
from datetime import datetime


class CertificateBase:
    """
    This class implements all base functionalities for certificate operations.
    """

    def __init__(self, args: argparse.Namespace):
        self._args = args
        self._pem_regex = re.compile("(?P<certificate>-+\s*BEGIN CERTIFICATE\s*-+.*?-+\s*END CERTIFICATE\s*-+)",
                                     re.DOTALL)

    @staticmethod
    def read_certificates(certificate_file: str, pem_regex):
        """
        Extracts all certificates from the given file using the given regular expression.
        """
        result = []
        # Load template certificates
        with open(certificate_file, "r") as file:
            content = file.read()
            for certificate in pem_regex.finditer(content):
                certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate.group("certificate"))
                result.append(certificate)
        return result

    @staticmethod
    def get_add_argparse_arguments(sub_parser: argparse._SubParsersAction):
        """
        This method adds the class specific command line arguments.
        """
        raise NotImplementedError("Method not implemented")

    @staticmethod
    def print_hex(item: int, line_break_after_bytes: int = None) -> list:
        result = "{:02x}".format(item)
        if (len(result) % 2) != 0:
            result = "0" + result
        if line_break_after_bytes:
            tmp = ""
            for i in range(len(result)):
                tmp += result[i]
                if i >= line_break_after_bytes and i % (line_break_after_bytes * 2) == 0:
                    tmp += os.linesep
            result = [':'.join(re.findall('..', line)) for line in tmp.split(os.linesep)]
            result = [line + ":" for line in result if line]
        else:
            result = [':'.join(re.findall('..', result))]
        return result

    @staticmethod
    def print_x509_name(item: crypto.X509Name):
        return "".join(
            ", {:s}={:s}".format(name.decode(), value.decode()) for name, value in item.get_components()).strip(", ")

    @staticmethod
    def x509_date_to_datetime(item) -> datetime:
        return datetime.strptime(item.decode('ascii'), '%Y%m%d%H%M%SZ')

    @staticmethod
    def print_x509_date(item):
        item_date = CertificateBase.x509_date_to_datetime(item)
        month = datetime.strftime(item_date, '%b')
        day = re.sub("^0", " ", datetime.strftime(item_date, '%d'))
        rest = datetime.strftime(item_date, "%H:%M:%S %Y GMT")
        return "{month} {day} {rest}".format(month=month, day=day, rest=rest)
