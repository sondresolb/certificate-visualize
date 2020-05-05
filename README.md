# Certificate Security Visualization

A desktop application for validating and analysing the security of a domain-certificate and relevant security mechanisms. It provides details surrounding the certificate chain, Certificate Revocation lists (CRL), Online Certificate Status Protocol (OCSP), Certificate Transparency (CT), Certificate Authority Authorization (CAA), HTTP Strict Transport Security (HSTS), OCSP-Staple, must-staple, supported TLS protocols, ciphers-suites and more. A score is calculated after the analysis and a light is shown to indicate the approximate security level. The application intendes to make the details of web security and the PKI accessable to a more general audience with limited knowledge about the subject.

## Getting Started

Instructions for cloning and using application

### Prerequisites

```
Python 3, OpenSSL 1.1.1, pip, pipenv, bash
```

### Installing

How to get the application and environment up and running


Clone the repository

```
git clone "repo"
```
Change directory into the root folder of certificate-visualize

```
cd cert_visualize
```

Install dependencies using pipenv

```
pipenv install & pipenv shell
```

Run the GUI application

```
python main_visualize.py
```

## Built With

* [pyca/cryptography](https://cryptography.io/en/latest/) - Cryptographic functions and primitives
* [pyOpenSSL](https://www.pyopenssl.org/en/stable/index.html) - SSL/TLS functionality
* [wbond/certvalidator](https://github.com/wbond/certvalidator) - Library for validating X.509 certificates and paths
* [requests](https://requests.readthedocs.io/en/master/) - Resource fetching
* [certifi](https://certifi.io/en/latest/) - Certificate trust store
* [pem](https://pypi.org/project/pem/) - Loading trust store
* [dnspython](http://www.dnspython.org/) - DNS CAA record fetching
* [tld](https://tld.readthedocs.io/en/latest/) - Identifying Top Level Domains for CAA
* [idna](https://pypi.org/project/idna/) - Domain encoding
* [pyqt5](https://pypi.org/project/PyQt5/) - Graphical user interface
* [Google's CT project](https://www.gstatic.com/ct/log_list/v2/log_list.json) - List of known CT logs and details
* [ciphersuite.info](https://ciphersuite.info/) - API for cipher-suite details and security rating


## Author

* **Sondre Solbakken** - https://github.com/sondresolb

## Acknowledgments
* Thank you to [attaque](https://stackoverflow.com/users/1116508/attaque) for the expiration calculation [function](https://stackoverflow.com/questions/1345827/how-do-i-find-the-time-difference-between-two-datetime-objects-in-python/47207182#47207182) and to [ise.io](https://www.ise.io/using-openssl-determine-ciphers-enabled-server/) for the method to determine enabled ciphers-suites on a server.
* Wikipedia for the initial green status light [file](https://en.m.wikipedia.org/wiki/File:Green_sphere.svg)