#!/bin/bash
rm -f unibench_cve.csv cvss.csv.zip cvss.csv
wget https://p.py3.io/unibench_cve.csv
wget https://p.py3.io/cvss.csv.zip
unzip cvss.csv.zip
