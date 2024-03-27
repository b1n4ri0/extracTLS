
# extracTLS
This Python script allows you to export TLS certificates from network capture files (.cap or .pcap), delete duplicates, and generate fake TLS certificates based on the selected one.

It utilizes the pyshark library for packet parsing and cryptography for certificate manipulation.


## Installation

Install extracTLS dependencies with pipreqs

```bash
git clone https://github.com/b1n4ri0/extracTLS

pip3 install -r extracTLS/requirements.txt
```
    
## Features

- Export TLS certificates from network capture files.
- Remove duplicate certificates.
- Generate fake TLS certificates based on the selected one.


## Usage/Examples

The tool is used as follows:

```bash
python3 extracTLS.py <capfile.cap> -o fake_cert.pem
```
An example usage scenario might involve:
```bash
sudo airodump-ng wlan0mon -c44 --encrypt WPA2 -w nwcap
```
It is advisable to wait for a certain period, approximately 2 minutes or until we have around 1600 beacons.
```bash
python3 extracTLS.py nwcap-01.cap
```

[Video](https://vimeo.com/927980852)

## Known Issues

The following error is likely to appear in older versions of cryptography:


`AttributeError: 'builtins.Certificate' object has no attribute 'not_valid_before_utc'`

In this case it is still possible to make the script work by making the following modifications. Delete the `_utc` from:

```diff
-       .not_valid_before(newcert.not_valid_before_utc)
-       .not_valid_after(newcert.not_valid_after_utc)

+       .not_valid_before(newcert.not_valid_before)
+       .not_valid_after(newcert.not_valid_after)
```
