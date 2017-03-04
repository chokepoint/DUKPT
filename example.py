#!/usr/bin/env python

from __future__ import print_function
import dukpt

server = dukpt.Server()
print("BDK: %s" % server.bdk.encode('hex'))
print("KSN and IPEK should be loaded to the Client() instance")
print("Multiple clients can be deployed by generating a new KSN and IPEK without compromising the BDK")
ksn = server.generate_ksn()
print("KSN: %s" % ksn.bytes.encode('hex'))
ipek = server.generate_ipek(ksn)
print("IPEK: %s" % ipek.bytes.encode('hex'))

client = dukpt.Client(ipek, ksn)
info = client.gen_key()

print("Client generated key: %s" % info['key'].encode('hex'))
print("Server generated key: %s" % server.gen_key(info['ksn']).encode('hex'))
