#!/usr/bin/env python

import setuptools
from distutils.core import setup, Extension

setup(name='rdpycredssp',
	version='1.0.0',
	description='Remote Desktop Protocol in Python',
	long_description="""RDPY is a pure Python implementation of the Microsoft RDP (Remote Desktop Protocol) protocol (client and server side). RDPY is built over the event driven network engine Twisted. RDPY support standard RDP security layer, RDP over SSL and NLA authentication (through ntlmv2 authentication protocol).
    RDPY provides the following RDP and VNC binaries :
    RDP Man In The Middle proxy which is used for doing credential relay in credssp.""",
	author='Sylvain Peyrefitte,Eyal Karni',
	author_email='citronneur@gmail.com, ekarni@preempt.com',
	packages=[
			'rdpy', 
			'rdpy.core',
			'rdpy.security', 
			'rdpy.protocol', 
			'rdpy.protocol.rdp', 
			'rdpy.protocol.rdp.pdu', 
			'rdpy.protocol.rdp.nla',
			'rdpy.protocol.rdp.t125',
		],
	scripts = [
			'./bin/rdpy-rdpcredsspmitm.py',
		],
	install_requires=[
			'twisted',
          	'pyopenssl',
          	'service_identity',
          	'qt4reactor',
          	'rsa',
          	'pyasn1',
            'impacket'
	  	],
)
