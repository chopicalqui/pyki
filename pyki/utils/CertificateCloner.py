import re
import os
import enum
import getpass
import argparse
from utils.core import CertificateBase
from OpenSSL import crypto


class DumpType(enum.Enum):
    raw = enum.auto()
    pkcs12 = enum.auto()
    pkcs12_all = enum.auto()


class CertificateCloner(CertificateBase):
    """
    This class clones the given certificate chain.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Load template certificates
        self._certificate_chain = CertificateBase.read_certificates(self._args.template, self._pem_regex)
        self._cloned_certificate_chain = []
        self._dump = DumpType[self._args.dump]
        self._ca_pkcs12 = None
        # Open PKCS12 file, if specified
        if self._args.pkcs12:
            passphrase = getpass.getpass(prompt="Passphrase for PKCS12 file: ")
            with open(self._args.pkcs12, "rb") as file:
                self._ca_pkcs12 = crypto.load_pkcs12(file.read(), passphrase=passphrase)
        # Do some error checks
        if len(self._certificate_chain) == 0:
            raise ValueError("The template file does not contain a valid PEM certificate.")
        elif self._args.self_signed and len(self._certificate_chain) > 1:
            raise ValueError("If flag --self-signed is used, then there must only be one certificate in the template file.")
        # Root certificate should be the first element
        self._certificate_chain.reverse()

    @staticmethod
    def get_add_argparse_arguments(sub_parser: argparse._SubParsersAction):
        """
        This method adds the class specific command line arguments.
        """
        parser = sub_parser.add_parser('clone', help='This module allows cloning a given certificate chain.')
        parser.add_argument('-t', '--template',
                            type=str,
                            required=True,
                            help="""File containing all certificates in PEM (base64) format along the certificate chain,
which shall be cloned. The first certificate in the list is the entity certificate
and the last is the root CA's certificate.""", action='store')
        parser.add_argument('--subject',
                            type=str,
                            help="""Specify a common name for the entity certificate. If not specified, then the common
name of the entity's template certificate is used.

The format of the subject must be something like:
CN=www.google.com,OU=Google""")
        parser.add_argument('--san',
                            type=str,
                            nargs="*",
                            help="""Specify a subject alternative name (SAN) for the entity certificate. If not,
specified then the SAN of the entity's template certificate is used.

The format of the subject can be something like:
DNS:*.google.com""")
        parser.add_argument('-o', '--output',
                            type=str,
                            required=True,
                            help="Specifies the output directory where the newly created certificates are stored.")
        signing_group = parser.add_mutually_exclusive_group()
        signing_group.add_argument('--self-signed', dest="self_signed",
                                   action="store_true",
                                   help="""If set, then all certificates will be signed by their own key. In addition, the
issuer attribute will be set to the subject attribute.""")
        signing_group.add_argument('--pkcs12',
                                   type=str,
                                   help="""Path to a PKCS12 file, which contains the CA's private key that shall be used to
to sign the newly created certificate chain.

If this argument is specified, then the file specified by --file must not contain the root CA.""")
        parser.add_argument('-d', '--dump',
                            choices=[item.name for item in DumpType],
                            default=DumpType.pkcs12,
                            help="""Specify how you want to store the cloned certificate chain.
- pkcs12: Stores the entities private key and certificate together with the cloned bridge
    and root certificates in a PKCS12 file.
    The PKCS12 file's passphrase is a blank password.
    You can verify the exported certificate chain using the following command:
    $ openssl pkcs12 -info -in certs.p12 -noout
- pkcs12_all: Stores the private key and certificate of each item along the certificate chain in a separate PKCS12 file.
    Afterwards, you could import each PKCS12 file into the Microsoft Windows certificate store.
- dump: Stores all private keys, public keys and certificates in separate files.
    You can verify the exported certificate chain using the following command:
    $ openssl verify -verbose -CAfile <(cat intermediate-X-cert.pem ... root-cert.pem) entity-cert.pem""")

    @staticmethod
    def set_x509_name(subject: crypto.X509Name, common_name: str):
        for item in common_name.split(","):
            type, value = item.strip().split("=")
            type = type.lower()
            if type == "c":
                subject.C = value
            elif type == "st":
                subject.ST = value
            elif type == "l":
                subject.L = value
            elif type == "o":
                subject.O = value
            elif type == "ou":
                subject.OU = value
            elif type == "cn":
                subject.CN = value
            else:
                raise NotImplementedError("subject component '{}' not supported.".format(item))

    def _clone(self,
               template: crypto.X509,
               signing_key: crypto.PKey = None,
               subject: str = None,
               san: list = None):
        """
        This method creates a cloned certificate based on the given template and signs it with the given signing key.
        If the signing key is missing, then the new certificate will be self-signed.
        :param template: The certificate whose attributes will be cloned to the new certificate.
        :param signing_key: The CA's private key which shall be used to sign the new certificate. If it is missing,
        then the new certificate will be self-signed.
        :param subject: If specified, then this common name is used instead of the template's common name.
        :param san: If specified, then this subject alternative name (SAN) is used instead of the template's SAN.
        :return: Tuple (crypto.PKey, crypto.X509) where the first element contains the public and private key and
        the second element contains the X509 certificate of the newly created certificate.
        """
        print("""Creating new certificate based on:
- Issuer:  {}
- Subject: {}""".format(self.print_x509_name(template.get_subject()),
                        self.print_x509_name(template.get_issuer())))
        # Generate key
        key_bits = template.get_pubkey().bits()
        key_type = template.get_pubkey().type()
        key = crypto.PKey()
        key.generate_key(key_type, key_bits)
        # Create signing request
        cert = crypto.X509()
        cert.set_pubkey(key)
        cert.set_serial_number(template.get_serial_number())
        cert.set_issuer(template.get_issuer())
        cert.set_version(template.get_version())
        if subject:
            if self._args.self_signed:
                self.set_x509_name(cert.get_issuer(), subject)
            self.set_x509_name(cert.get_subject(), subject)
        else:
            if self._args.self_signed:
                cert.set_issuer(template.get_subject())
            cert.set_subject(template.get_subject())
        cert.set_notAfter(template.get_notAfter())
        cert.set_notBefore(template.get_notBefore())
        # Add extensions
        extensions = []
        for i in range(template.get_extension_count()):
            extension = template.get_extension(i)
            if san and extension.get_short_name() in ['subjectAltName', b'subjectAltName']:
                extension = crypto.X509Extension(b"subjectAltName", False, ", ".join(san).encode("utf-8"))
            extensions.append(extension)
        cert.add_extensions(extensions)
        # Sign key
        if signing_key:
            cert.sign(signing_key, template.get_signature_algorithm().decode("utf-8"))
        else:
            cert.sign(key, template.get_signature_algorithm().decode("utf-8"))
        return key, cert

    def clone(self):
        """
        This method iterates through the whole template certificate chain and creates a completely cloned certificate
        chain.
        :return:
        """
        ca_key, ca_cert = None, None
        certificate_count = len(self._certificate_chain)
        for i in range(certificate_count):
            certificate = self._certificate_chain[i]
            subject = self._args.subject if i == (certificate_count - 1) else None
            san = self._args.san if i == (certificate_count - 1) else None
            if self._ca_pkcs12:
                ca_key, ca_cert = self._clone(template=certificate,
                                              signing_key=self._ca_pkcs12.get_privatekey(),
                                              subject=subject,
                                              san=san)
            elif ca_key:
                ca_key, ca_cert = self._clone(template=certificate,
                                              signing_key=ca_key,
                                              subject=subject,
                                              san=san)
            else:
                ca_key, ca_cert = self._clone(template=certificate,
                                              subject=subject,
                                              san=san)
            self._cloned_certificate_chain.append((ca_key, ca_cert))
        # At the end we reverse the cloned certificate chain so that the entity certificate comes first.
        self._cloned_certificate_chain.reverse()

    def _write_file(self, path, content, mode="w"):
        """
        Helper method used to write certificate information to files.
        :param path: The full path to the file.
        :param content: The content of the file.
        :param mode: The mode how the file shall be opened.
        :return: None
        """
        if os.path.exists(path):
            raise FileExistsError("The file '{}' already exists.".format(path))
        with open(path, mode) as file:
            file.write(content)

    def dump(self):
        """
        This method dumps the content of the newly created certificate chain to disk,
        :return: None
        """
        if self._dump == DumpType.pkcs12:
            pkcs12 = crypto.PKCS12()
            certificate_count = len(self._cloned_certificate_chain)
            ca_certificates = []
            file_name = None
            for i in range(certificate_count):
                key, cert = self._cloned_certificate_chain[i]
                if i == 0:
                    pkcs12.set_privatekey(key)
                    pkcs12.set_certificate(cert)
                    file_name = os.path.join(self._args.output, "{}.pfx".format(cert.get_subject().CN))
                elif i < certificate_count:
                    ca_certificates.append(cert)
                else:
                    pkcs12.set_ca_certificates(ca_certificates)
            passphrase = getpass.getpass(prompt="Passphrase for PKCS12 file: ")
            self._write_file(os.path.join(self._args.output, file_name), pkcs12.export(passphrase=passphrase), mode="wb")
        elif self._dump == DumpType.pkcs12_all:
            certificate_count = len(self._cloned_certificate_chain)
            passphrase = getpass.getpass(prompt="Passphrase for PKCS12 files: ")
            for i in range(certificate_count):
                key, cert = self._cloned_certificate_chain[i]
                file_name = os.path.join(self._args.output, "{}_{}.pfx".format(i + 1, cert.get_subject().CN))
                pkcs12 = crypto.PKCS12()
                pkcs12.set_privatekey(key)
                pkcs12.set_certificate(cert)
                self._write_file(file_name, pkcs12.export(passphrase=passphrase), mode="wb")
        else:
            certificate_count = len(self._cloned_certificate_chain)
            for i in range(certificate_count):
                key, cert = self._cloned_certificate_chain[i]
                file_name = os.path.join(self._args.output, "{}_{}".format(i + 1, cert.get_subject().CN))
                self._write_file("{}.key".format(file_name),
                                 crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))
                self._write_file("{}.pub".format(file_name),
                                 crypto.dump_publickey(crypto.FILETYPE_PEM, key).decode("utf-8"))
                self._write_file("{}.pem".format(file_name),
                                 crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
