import OpenSSL
import ssl
import argparse
from utils.CertificateCloner import DumpType
from utils.CertificateCloner import CertificateCloner


def main(args: argparse.Namespace):
    c = CertificateCloner(args)
    c.clone()
    c.dump()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--certificates',
                        type=str,
                        help="""File containing all certificates in PEM (base64) format along the certificate chain.
The first certificate in the list is the entity certificate and the last is the root
CA's certificate""", action='store')
    parser.add_argument('-o', '--output',
                        type=str,
                        required=True,
                        help="Specifies the output directory or PKCS12 file.")
    parser.add_argument('-d', '--dump',
                        choices=[item.name for item in DumpType],
                        default=DumpType.pkcs12,
                        help="""Specify how you want to store the cloned certificate chain.
- pkcs12: Stores the entities private key and certificate together with the cloned bridge
    and root certificates in a PKCS12 file.
    The PKCS12 file's passphrase is a blank password.
    You can verify the exported certificate chain using the following command:
    $ openssl pkcs12 -info -in certs.p12 -noout
- dump: Stores all private keys, public keys and certificates in separate files.
    You can verify the exported certificate chain using the following command:
    $ openssl verify -verbose -CAfile <(cat intermediate-X-cert.pem ... root-cert.pem) entity-cert.pem""")
    args = parser.parse_args()
    main(args)
