import re
import os
import enum
import argparse
from OpenSSL import crypto


class DumpType(enum.Enum):
    raw = enum.auto()
    pkcs12 = enum.auto()


class CertificateCloner:
    """
    This class clones the given certificate chain.
    """
    def __init__(self, args: argparse.Namespace):
        self._args = args
        self._certificate_chain = []
        self._cloned_certificate_chain = []
        self._pem_regex = re.compile("(?P<certificate>-+\s*BEGIN CERTIFICATE\s*-+.*?-+\s*END CERTIFICATE\s*-+)",
                                     re.DOTALL)
        with open(args.certificates, "r") as file:
            content = file.read()
            for certificate in self._pem_regex.finditer(content):
                certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate.group("certificate"))
                self._certificate_chain.append(certificate)
        # Root certificate should be the first element
        self._certificate_chain.reverse()

    def _clone(self, template: crypto.X509, signing_key: crypto.PKey = None):
        """
        This method creates a cloned certificate based on the given template and signs it with the given signing key.
        If the signing key is missing, then the new certificate will be self-signed.
        :param template: The certificate whose attributes will be cloned to the new certificate.
        :param signing_key: The CA's private key which shall be used to sign the new certificate. If it is missing,
        then the new certificate will be self-signed.
        :return: Tuple (crypto.PKey, crypto.X509) where the first element contains the public and private key and
        the second element contains the X509 certificate of the newly created certificate.
        """
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
        cert.set_subject(template.get_subject())
        cert.set_notAfter(template.get_notAfter())
        cert.set_notBefore(template.get_notBefore())
        cert.add_extensions([template.get_extension(i) for i in range(template.get_extension_count())])

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
        for i in range(len(self._certificate_chain)):
            certificate = self._certificate_chain[i]
            if not ca_key:
                ca_key, ca_cert = self._clone(template=certificate)
            else:
                ca_key, ca_cert = self._clone(template=certificate, signing_key = ca_key)
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
        with open(path, mode) as file:
            file.write(content)

    def dump(self):
        """
        This method dumps the content of the newly created certificate chain to disk,
        :return: None
        """
        if DumpType[self._args.dump] == DumpType.pkcs12:
            pkcs12 = crypto.PKCS12()
            certificate_count = len(self._cloned_certificate_chain)
            ca_certificates = []
            for i in range(certificate_count):
                key, cert = self._cloned_certificate_chain[i]
                if i == 0:
                    pkcs12.set_privatekey(key)
                    pkcs12.set_certificate(cert)
                elif i < certificate_count:
                    ca_certificates.append(cert)
                else:
                    pkcs12.set_ca_certificates(ca_certificates)
            self._write_file(self._args.output, pkcs12.export(passphrase=""), mode="wb")
        else:
            certificate_count = len(self._cloned_certificate_chain)
            for i in range(certificate_count):
                key, cert = self._cloned_certificate_chain[i]
                if i == 0:
                    self._write_file(os.path.join(self._args.output, "entity-cert.key"),
                                     crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))
                    self._write_file(os.path.join(self._args.output, "entity-cert.pub"),
                                     crypto.dump_publickey(crypto.FILETYPE_PEM, key).decode("utf-8"))
                    self._write_file(os.path.join(self._args.output, "entity-cert.pem"),
                                     crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
                elif i < certificate_count - 1:
                    self._write_file(os.path.join(self._args.output, "intermediate-{}-cert.key".format(i - 1)),
                                     crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))
                    self._write_file(os.path.join(self._args.output, "intermediate-{}-cert.pub".format(i - 1)),
                                     crypto.dump_publickey(crypto.FILETYPE_PEM, key).decode("utf-8"))
                    self._write_file(os.path.join(self._args.output, "intermediate-{}-cert.pem".format(i - 1)),
                                     crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
                else:
                    self._write_file(os.path.join(self._args.output, "root-cert.key"),
                                     crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode("utf-8"))
                    self._write_file(os.path.join(self._args.output, "root-cert.pub"),
                                     crypto.dump_publickey(crypto.FILETYPE_PEM, key).decode("utf-8"))
                    self._write_file(os.path.join(self._args.output, "root-cert.pem"),
                                     crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
