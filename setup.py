from setuptools import setup, find_packages

name = "python_scan"
version = "0.4.4.a3"
descripcion = "Herramienta para escaneo de puertos/vulners/explits en una IP"
author = "__TownPablo__"
author_email = "pablodiez024@proton.me"
url = "https://github.com/an0m4l1a/PORT_SCANNER"
install_requires = [
    "colorama==0.4.6",
    "comtypes==1.1.14",
    "nvdlib==0.7.3",
    "pyExploitDb==0.2.9",
    "pyfiglet==0.8.post1",
    "sockets==1.0.0",
    "python-nmap==0.7.1"
]

keywords = ["port scan", "seguridad", "redes"]
packages = find_packages()
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
license = "MIT"

setup(
    name=name,
    version=version,
    description=descripcion,
    author=author,
    author_email=author_email,
    url=url,
    install_requires=install_requires,
    keywords=keywords,
    packages=packages,
    long_description=long_description,
    long_description_content_type="text/markdown",
    license=license,
    scripts=['PORT_SCAN.py'],
)
