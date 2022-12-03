import os
import csv
import sys
import enum
import getpass
import argparse
from OpenSSL import crypto
from utils.core import CertificateBase
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers


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
        for item in self._args.files:
            if self._args.pkcs12:
                if self._args.passphrase:
                    passphrase = self._args.passphrase
                else:
                    passphrase = getpass.getpass(prompt="Passphrase for PKCS12 file: ")
                with open(item, "rb") as file:
                    pkcs12 = crypto.load_pkcs12(file.read(), passphrase=passphrase)
                    root_ca = pkcs12.get_ca_certificates()
                    if root_ca:
                        self._certificates += root_ca
                    self._certificates.append(pkcs12.get_certificate())
            else:
                self._certificates += CertificateBase.read_certificates(item, self._pem_regex)

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
                                 "Each file can contain several certificates.")
        parser.add_argument('--pkcs12', action='store_true', help="If specified, then the given files are PKCS12 and "
                                                                  "not text files containing all certificates in "
                                                                  "PEM (base64) format.")
        parser.add_argument('-p', '--passphrase',
                            type=str,
                            help="Passphrase to read PKCS12 file.")
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
                   "Public Key Algorithm",
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
            c = certificate.to_cryptography()
            public_key = certificate.get_pubkey().to_cryptography_key().public_numbers()
            not_before = self.x509_date_to_datetime(certificate.get_notBefore())
            not_after = self.x509_date_to_datetime(certificate.get_notAfter())
            if isinstance(public_key, RSAPublicNumbers):
                public_key_name = "RSA"
            elif isinstance(public_key, DSAPublicNumbers):
                public_key_name = "DSA"
            elif isinstance(public_key, EllipticCurvePublicNumbers):
                public_key_name = public_key.curve.name
            else:
                raise NotImplementedError("case not implemented")
            for i in range(certificate.get_extension_count()):
                extension = certificate.get_extension(i)
                short_name, data = self.get_extension(extension, c.extensions[i].oid.dotted_string)
                extensions[short_name] = {"value": data,
                                          "critical": extension.get_critical() == 1}
            if isinstance(public_key, RSAPublicNumbers) or isinstance(public_key, DSAPublicNumbers):
                public_key_bits = certificate.get_pubkey().bits()
                exponent = public_key.e
            elif isinstance(public_key, EllipticCurvePublicNumbers):
                public_key_bits = None
                exponent = None
            else:
                raise NotImplementedError("case not implemented")
            result.append([certificate.get_version(),  # Version
                           "".join(self.print_hex(certificate.get_serial_number())),  # Serial Number
                           certificate.get_signature_algorithm().decode(),  # Signature Algorithm
                           public_key_name,  # Public Key Algorithm
                           self.print_x509_name(certificate.get_issuer()),  # Issuer
                           self.print_x509_name(certificate.get_subject()),  # Subject
                           not_before.strftime("%Y-%m-%d %H:%M:%S %Y GMT"),  # Valid Not Before
                           not_after.strftime("%Y-%m-%d %H:%M:%S %Y GMT"),  # Valid Not After
                           public_key_bits,  # Public Key Size
                           exponent,  # Exponent
                           extensions["keyUsage"]["value"] if "keyUsage" in extensions else None,  # keyUsage
                           extensions["extendedKeyUsage"]["value"] if "extendedKeyUsage" in extensions else None,  # extendedKeyUsage
                           extensions["subjectKeyIdentifier"]["value"] if "subjectKeyIdentifier" in extensions else None,  # subjectKeyIdentifier
                           extensions["authorityKeyIdentifier"]["value"] if "authorityKeyIdentifier" in extensions else None,  # authorityKeyIdentifier
                           extensions["subjectAltName"]["value"] if "subjectAltName" in extensions else None  # subjectAltName
                           ])
        csv_writer = csv.writer(sys.stdout)
        csv_writer.writerows(result)

    def _print_text(self):
        j = 1
        for certificate in self._certificates:
            c = certificate.to_cryptography()
            signature_algorithm = certificate.get_signature_algorithm().decode()
            public_key = certificate.get_pubkey().to_cryptography_key().public_numbers()
            print("Certificate {}:".format(j))
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
            if isinstance(public_key, RSAPublicNumbers):
                print("            Public Key Algorithm: rsaEncryption")
                print("                Public-Key: ({bits} bit)".format(bits=certificate.get_pubkey().bits()))
                print("                Modulus:")
                for line in self.print_hex(public_key.n, line_break_after_bytes=15):
                    print("                    {}".format(line))
                print("                Exponent: {} ({})".format(public_key.e, hex(public_key.e)))
            elif isinstance(public_key, DSAPublicNumbers):
                print("            Public Key Algorithm: dsaEncryption")
                print("                Public-Key: ({bits} bit)".format(bits=certificate.get_pubkey().bits()))
                print("                Modulus:")
                for line in self.print_hex(public_key.n, line_break_after_bytes=15):
                    print("                    {}".format(line))
                print("                Exponent: {} ({})".format(public_key.e, hex(public_key.e)))
            elif isinstance(public_key, EllipticCurvePublicNumbers):
                print("            Public Key Algorithm: id-ecPublicKey")
                print("                Public-Key: ({bits} bit)".format(bits=certificate.get_pubkey().bits()))
                # print("                Pub:")
                # for line in self.print_hex(public_key., line_break_after_bytes=15):
                #     print("                    {}".format(line))
                print("                Curve Name: {}".format(public_key.curve.name))
            else:
                raise NotImplementedError("case not implemented")
            print("        X509v3 extensions:")
            for i in range(certificate.get_extension_count()):
                extension = certificate.get_extension(i)
                short_name, data = self.get_extension(extension, c.extensions[i].oid.dotted_string)
                print("            {}: {}".format(short_name, "critical" if extension.get_critical() else ""))
                for line in data.split("\n"):
                    print("                {}".format(line))
            j += 1
            print()
