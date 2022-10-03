# pyki
Python project which implements certificate operations like cloning or printing certificates.

# Operations
## Clone

The following command clones the certificate chain stored in testdata/stackexchange.pem
and stores each newly created private/public keys plus corresponding certificate in a
separate PKCS12 file. The PKCS12 files are stored in /tmp/test.

```bash
python3 pyki clone -t testdata/stackexchange.pem -d pkcs12_all -o /tmp/test
```

## Print

PEM certificates can be printed in text (similar to OpenSSL output) and CSV format using
the following command

```bash
# Printing the certificates located in testdata/stackexchange.pem as text
python3 pyki print testdata/stackexchange.pem -f text
# Printing the certificates located in testdata/stackexchange.pem as CSV
python3 pyki print testdata/stackexchange.pem -f csv
```
