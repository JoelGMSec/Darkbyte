#
# Copyright (c) 2014-2015 Sylvain Peyrefitte
#
# This file is part of rdpy.
#
# rdpy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

"""
@summary: Credential Security Support Provider
@see: https://msdn.microsoft.com/en-us/library/cc226764.aspx
"""

from pyasn1.type import namedtype, univ, tag
import pyasn1.codec.der.encoder as der_encoder
import pyasn1.codec.der.decoder as der_decoder
import pyasn1.codec.ber.encoder as ber_encoder

from rdpy.core.type import Stream
from twisted.internet import protocol
from OpenSSL import crypto
from rdpy.security import x509
from rdpy.core import error

import ntlm
from rdpy.core import type

class NegoToken(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('negoToken', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
    )

class NegoData(univ.SequenceOf):
    """
    @summary: contain spnego ntlm of kerberos data
    @see: https://msdn.microsoft.com/en-us/library/cc226781.aspx
    """
    componentType = NegoToken()

class TSRequest(univ.Sequence):
    """
    @summary: main structure
    @see: https://msdn.microsoft.com/en-us/library/cc226780.aspx
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('negoTokens', NegoData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('authInfo', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.OptionalNamedType('pubKeyAuth', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
        namedtype.OptionalNamedType('errorCode', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)))
        )

class TSCredentials(univ.Sequence):
    """
    @summary: contain user information
    @see: https://msdn.microsoft.com/en-us/library/cc226782.aspx
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('credType', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('credentials', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
        )
    
class TSPasswordCreds(univ.Sequence):
    """
    @summary: contain username and password
    @see: https://msdn.microsoft.com/en-us/library/cc226783.aspx
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('domainName', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('userName', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('password', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))
        )

class TSCspDataDetail(univ.Sequence):
    """
    @summary: smart card credentials
    @see: https://msdn.microsoft.com/en-us/library/cc226785.aspx
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keySpec', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('cardName', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('readerName', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.OptionalNamedType('containerName', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
        namedtype.OptionalNamedType('cspName', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4)))
        )

class TSSmartCardCreds(univ.Sequence):
    """
    @summary: smart card credentials
    @see: https://msdn.microsoft.com/en-us/library/cc226784.aspx
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pin', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('cspData', TSCspDataDetail().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('userHint', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.OptionalNamedType('domainHint', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)))
        )

class OpenSSLRSAPublicKey(univ.Sequence):
    """
    @summary: asn1 public rsa key
    @see: https://tools.ietf.org/html/rfc3447
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('unknow', univ.Integer()),
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer()),
        )

def encodeDERTRequestOriginal(negoTypes = [], authInfo = None, pubKeyAuth = None):
    """
    @summary: create TSRequest from list of Type
    @param negoTypes: {list(Type)}
    @param authInfo: {str} authentication info TSCredentials encrypted with authentication protocol
    @param pubKeyAuth: {str} public key encrypted with authentication protocol
    @return: {str} TRequest der encoded
    """
    negoData = NegoData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))

    #fill nego data tokens
    i = 0
    for negoType in negoTypes:
        s = Stream()
        s.writeType(negoType)
        negoToken = NegoToken()
        negoToken.setComponentByPosition(0, s.getvalue())
        negoData.setComponentByPosition(i, negoToken)
        i += 1

    request = TSRequest()
    request.setComponentByName("version", univ.Integer(2).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))

    if i > 0:
        request.setComponentByName("negoTokens", negoData)

    if not authInfo is None:
        request.setComponentByName("authInfo", univ.OctetString(authInfo).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))

    if not pubKeyAuth is None:
        request.setComponentByName("pubKeyAuth", univ.OctetString(pubKeyAuth).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)))

    return der_encoder.encode(request)

def encodeDERTRequest(negoTypes = [], authInfo = None, pubKeyAuth = None):
    """
    @summary: create TSRequest from list of Type
    @param negoTypes: {list(Type)}
    @param authInfo: {str} authentication info TSCredentials encrypted with authentication protocol
    @param pubKeyAuth: {str} public key encrypted with authentication protocol
    @return: {str} TRequest der encoded
    """
    negoData = NegoData().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
    
    #fill nego data tokens
    i = 0
    for negoType in negoTypes:
        negoToken = NegoToken()
        negoToken.setComponentByPosition(0, negoType)
        negoData.setComponentByPosition(i, negoToken)
        i += 1
        
    request = TSRequest()
    request.setComponentByName("version", univ.Integer(2).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
    
    if i > 0:
        request.setComponentByName("negoTokens", negoData)
    
    if not authInfo is None:
        request.setComponentByName("authInfo", univ.OctetString(authInfo).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))
    
    if not pubKeyAuth is None:
        request.setComponentByName("pubKeyAuth", univ.OctetString(pubKeyAuth).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))) 
        
    return der_encoder.encode(request)

def decodeDERTRequest(s):
    """
    @summary: Decode the stream as
    @param s: {str}
    """
    return der_decoder.decode(s, asn1Spec=TSRequest())[0]

def getNegoTokens(tRequest):
    negoData = tRequest.getComponentByName("negoTokens")
    return [Stream(negoData.getComponentByPosition(i).getComponentByPosition(0).asOctets()) for i in range(len(negoData))]
    
def getPubKeyAuth(tRequest):
    return tRequest.getComponentByName("pubKeyAuth").asOctets()

def encodeDERTCredentials(domain, username, password):
    passwordCred = TSPasswordCreds()
    passwordCred.setComponentByName("domainName", univ.OctetString(domain).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
    passwordCred.setComponentByName("userName", univ.OctetString(username).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    passwordCred.setComponentByName("password", univ.OctetString(password).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)))
    
    credentials = TSCredentials()
    credentials.setComponentByName("credType", univ.Integer(1).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
    credentials.setComponentByName("credentials", univ.OctetString(der_encoder.encode(passwordCred)).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    
    return der_encoder.encode(credentials)

class CSSP(protocol.Protocol):
    """
    @summary: Handle CSSP connection
    Proxy class for authentication
    """
    def __init__(self, listener, layer, authenticationProtocol):
        """
        @param layer: {type.Layer.RawLayer}
        @param authenticationProtocol: {sspi.IAuthenticationProtocol}
        """
        self._layer = layer
        self._authenticationProtocol = authenticationProtocol
        #IGenericSecurityService
        self._interface = None
        #function call at the end of nego
        self._callback = None
        self._listener=listener

    def setFactory(self, factory):
        """
        @summary: Call by RawLayer Factory
        @param param: RawLayerClientFactory or RawLayerFactory
        """
        self._layer.setFactory(factory)
        
    def dataReceived(self, data):
        """
        @summary:  Inherit from twisted.protocol class
                    main event of received data
        @param data: string data receive from twisted
        """
        self._layer.dataReceived(data)
    
    def connectionLost(self, reason):
        """
        @summary: Call from twisted engine when protocol is closed
        @param reason: str represent reason of close connection
        """
        self._layer._factory.connectionLost(self, reason)
            
    def connectionMade(self):
        """
        @summary: install proxy
        """
        self._layer.transport = self
        self._layer.getDescriptor = lambda:self.transport
        self._layer.connectionMade()
    
    def write(self, data):
        """
        @summary: write data on transport layer
        @param data: {str}
        """
        self.transport.write(data)
    
    def startTLS(self, sslContext):
        """
        @summary: start TLS protocol
        @param sslContext: {ssl.ClientContextFactory | ssl.DefaultOpenSSLContextFactory} context use for TLS protocol
        """
        self.transport.startTLS(sslContext)
        