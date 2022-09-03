import os
import csv
import sys
import enum
import argparse
from utils.core import CertificateBase


class ReportFormat(enum.Enum):
    csv = enum.auto()
    text = enum.auto()


class CertificatePrinter(CertificateBase):
    """
    This class clones the given certificate chain.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._certificates = []
        self._format = ReportFormat[self._args.format]
        # Load template certificates
        for file in self._args.files:
            self._certificates += CertificateBase.read_certificates(file, self._pem_regex)

    @staticmethod
    def get_add_argparse_arguments(sub_parser: argparse._SubParsersAction):
        """
        This method adds the class specific command line arguments.
        """
        parser = sub_parser.add_parser('print', help='This module prints the content of all given certificates files.')
        parser.add_argument('files',
                            type=str,
                            nargs="+",
                            help="File containing all certificates in PEM (base64) format, which shall be printed. "
                                 "Each file can contain several certificates.", action='store')
        parser.add_argument('-f', '--format',
                            choices=[item.name for item in ReportFormat],
                            default=ReportFormat.text.name,
                            help="Specifies in which format (text, CSV) the certificate information shall be printed.")

    def print(self):
        if self._format == ReportFormat.text:
            self._print_text()
        elif self._format == ReportFormat.csv:
            self._print_csv()
        else:
            raise NotImplementedError()

    def _print_csv(self):
        result = [["Version",
                   "Serial Number",
                   "Signature Algorithm",
                   "Issuer",
                   "Subject",
                   "Valid Not Before",
                   "Valid Not After",
                   "Public Key Size",
                   "Exponent",
                   "keyUsage",
                   "extendedKeyUsage",
                   "subjectKeyIdentifier",
                   "authorityKeyIdentifier",
                   "subjectAltName"]]
        for certificate in self._certificates:
            extensions = {}
            public_key = certificate.get_pubkey().to_cryptography_key().public_numbers()
            not_before = self.x509_date_to_datetime(certificate.get_notBefore())
            not_after = self.x509_date_to_datetime(certificate.get_notAfter())
            for i in range(certificate.get_extension_count()):
                extension = certificate.get_extension(i)
                extension_name = extension.get_short_name().decode("utf-8")
                extensions[extension_name] = {"value": str(extension),
                                              "critical": extension.get_critical() == 1}
            result.append([certificate.get_version(),  # Version
                           "".join(self.print_hex(certificate.get_serial_number())),  # Serial Number
                           certificate.get_signature_algorithm().decode("utf-8"),  # Signature Algorithm
                           self.print_x509_name(certificate.get_issuer()),  # Issuer
                           self.print_x509_name(certificate.get_subject()),  # Subject
                           not_before.strftime("%Y-%m-%d %H:%M:%S %Y GMT"),  # Valid Not Before
                           not_after.strftime("%Y-%m-%d %H:%M:%S %Y GMT"),  # Valid Not After
                           certificate.get_pubkey().bits(),  # Public Key Size
                           public_key.e,  # Exponent
                           extensions["keyUsage"]["value"] if "keyUsage" in extensions else None,  # keyUsage
                           extensions["extendedKeyUsage"]["value"] if "extendedKeyUsage" in extensions else None,  # extendedKeyUsage
                           extensions["subjectKeyIdentifier"]["value"] if "subjectKeyIdentifier" in extensions else None,  # subjectKeyIdentifier
                           extensions["authorityKeyIdentifier"]["value"] if "authorityKeyIdentifier" in extensions else None,  # authorityKeyIdentifier
                           extensions["subjectAltName"]["value"] if "subjectAltName" in extensions else None  # subjectAltName
                           ])
        csv_writer = csv.writer(sys.stdout)
        csv_writer.writerows(result)

    def _print_text(self):
        for certificate in self._certificates:
            signature_algorithm = certificate.get_signature_algorithm().decode("utf-8")
            public_key = certificate.get_pubkey().to_cryptography_key().public_numbers()
            print("Certificate:")
            print("    Data:")
            print("        Version: {version} ({version_hex})".format(version=certificate.get_version(),
                                                                      version_hex=hex(certificate.get_version())))
            print("        Serial Number:")
            print("            {sn}".format(sn="".join(self.print_hex(certificate.get_serial_number()))))
            print("    Signature Algorithm: {}".format(signature_algorithm))
            print("        Issuer: {}".format(self.print_x509_name(certificate.get_issuer())))
            print("        Validity")
            print("            Not Before: {}".format(self.print_x509_date(certificate.get_notBefore())))
            print("            Not After : {}".format(self.print_x509_date(certificate.get_notAfter())))
            print("        Subject: {}".format(self.print_x509_name(certificate.get_subject())))
            print("        Subject Public Key Info:")
            print("                Public-Key: ({bits} bit)".format(bits=certificate.get_pubkey().bits()))
            print("                Modulus:")
            for line in self.print_hex(public_key.n, line_break_after_bytes=15):
                print("                    {}".format(line))
            print("                Exponent: {} ({})".format(public_key.e, hex(public_key.e)))
            print("        X509v3 extensions:")
            for i in range(certificate.get_extension_count()):
                extension = certificate.get_extension(i)
                print("            {}: {}".format(extension.get_short_name().decode("utf-8"),
                                                  "critical" if extension.get_critical() else ""))
                for line in str(extension).split(os.linesep):
                    print("                {}".format(line))