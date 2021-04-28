#!/usr/local/bin/python3.9
# -*- coding: UTF-8 -*

import struct
import socket
import random
import time
import optparse

typeDict = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR",
    39: "DNAME", 99: "SPF", 257: "CAA"
}
recodesDict = {
    0: "NOERROR", 1: "FORMERR", 2: "Servfail", 3: "NXDOMAIN", 5: "Refused", 9: "NOTAUTH"
}


class PythonDig:
    def __init__(self, domain, server='127.0.0.1', port=53, queryType='A', opt=None, timeout=10, pro='udp'):
        self.domain = domain
        self.server = server
        self.port = port
        self.queryType = queryType.upper()
        self.opt = opt
        self.timeout = timeout
        self.pro = pro

    def compression(self, domFind):
        name = ''
        tmp = self.res[int('{:08b}'.format(int.from_bytes(domFind, byteorder='big', signed=False))[2:], 2):]
        for dom_index, dom in enumerate(tmp):
            if dom == 0:
                name = name + '.'
                break
            elif '{:08b}'.format(dom)[:2] == '11' and dom_index == 0:
                name = name + self.compression(tmp[dom_index:dom_index + 2])
                break
            elif '{:08b}'.format(dom)[:2] == '11':
                # elif str(bin(dom))[:3] == '11':
                name = name + '.'
                name = name + self.compression(tmp[dom_index:dom_index + 2])
                break
            else:
                if dom_index == 0 and not chr(dom).isalpha() and not chr(dom).isdigit() and chr(dom) != '-' and chr(dom) != '_':
                    continue
                elif not chr(dom).isalpha() and not chr(dom).isdigit() and chr(dom) != '-' and chr(dom) != '_':
                    name = name + '.'
                else:
                    name = name + chr(dom)
        return name

    def nsRes(self, nsLen):
        nsAddr = ''
        for ys_index, ys in enumerate(self.res[self.answerStart + self.answerNode + nsLen:]):
            if ys == 0:
                self.nsIndex = ys_index + 1
                nsAddr = nsAddr + '.'
                break
            elif '{:08b}'.format(ys)[:2] == '11' and ys_index == 0:
                self.nsIndex = ys_index + 2
                self.answerIndex = ys_index
                nsAddr = nsAddr + self.compression(self.res[self.answerStart + self.answerNode + nsLen:][self.answerIndex:self.answerIndex + 2])
                # self.answerIndex = self.answerIndex + 2
                break
            elif '{:08b}'.format(ys)[:2] == '11':
                self.nsIndex = ys_index + 2
                nsAddr = nsAddr + '.'
                self.answerIndex = ys_index
                nsAddr = nsAddr + self.compression(self.res[self.answerStart + self.answerNode + nsLen:][self.answerIndex:self.answerIndex + 2])
                # self.answerIndex = self.answerIndex + 2
                break
            else:
                if not chr(ys).isalpha() and not chr(ys).isdigit() and chr(ys) != '-' and chr(ys) != '_' and ys_index == 0:
                    continue
                elif not chr(ys).isalpha() and not chr(ys).isdigit() and chr(ys) != '-' and chr(ys) != '_':
                    nsAddr = nsAddr + '.'
                else:
                    nsAddr = nsAddr + chr(ys)
        return nsAddr

    def aRes(self):
        ipaddr = ''
        for ipAddr in self.res[self.answerStart + self.answerNode + 12:self.answerStart + self.answerNode + 16]:
            ipaddr = str(ipaddr) + '.' + str(ipAddr)
        return ipaddr[1:]

    def aaaaRes(self):
        aaaaipaddr = ''
        count = 0
        newAddr = ''
        addrList = []
        tmp1 = 0
        tmp2 = 0
        indexZero = 0
        for aaaa in self.res[self.answerStart + self.answerNode + 12:self.answerStart + self.answerNode + 28]:
            count = count + 1
            if len(hex(aaaa)) < 4:
                aaaaipaddr = aaaaipaddr + '0' + str(hex(aaaa))[2:]
            else:
                aaaaipaddr = aaaaipaddr + str(hex(aaaa))[2:]
            if count % 2 == 0:
                aaaaipaddr = aaaaipaddr + ':'
        for i in aaaaipaddr.split(':'):
            for k, v in enumerate(i):
                if v != '0':
                    addrList.append(i[k:])
                    break
                elif v == '0' and k == 3:
                    addrList.append(0)

        for j, l in enumerate(addrList):
            if l == 0:
                tmp1 += 1
            elif l != 0 and tmp1 > tmp2:
                indexZero = j
                tmp2 = tmp1
                tmp1 = 0
        for i in range(tmp2):
            addrList[indexZero - tmp2 + i] = ''
        for i in addrList:
            if i == '' and '::' in newAddr:
                pass
            else:
                newAddr = newAddr + str(i) + ':'
        return newAddr[:-1]

    def domainResName(self):
        domainListName = ''
        for ys_index, ys in enumerate(self.res[self.answerStart + self.answerNode:]):
            if '{:08b}'.format(ys)[:2] == '11' and ys_index == 0:
                domainListName = domainListName + self.compression(self.res[self.answerStart + self.answerNode:][0:2])
                break
            else:
                if not chr(ys).isalpha() and not chr(ys).isdigit() and chr(ys) != '-' and chr(ys) != '_' and ys_index == 0:
                    continue
                elif not chr(ys).isalpha() and not chr(ys).isdigit() and chr(ys) != '-' and chr(ys) != '_':
                    domainListName = domainListName + '.'
                else:
                    domainListName = domainListName + chr(ys)
        return domainListName

    def cnameResAddr(self):
        cnameAddr = ''
        for ys_index, ys in enumerate(self.res[self.answerStart + self.answerNode + 12:]):
            if ys == 0:
                self.answerIndex = ys_index + 1
                cnameAddr = cnameAddr + '.'
                break
            elif '{:08b}'.format(ys)[:2] == '11':
                cnameAddr = cnameAddr + '.'
                self.answerIndex = ys_index
                cnameAddr = cnameAddr + self.compression(self.res[self.answerStart + self.answerNode + 12:][self.answerIndex:self.answerIndex + 2])
                self.answerIndex = self.answerIndex + 2
                break
            else:
                if not chr(ys).isalpha() and not chr(ys).isdigit() and chr(ys) != '-' and chr(ys) != '_' and ys_index == 0:
                    continue
                elif not chr(ys).isalpha() and not chr(ys).isdigit() and chr(ys) != '-' and chr(ys) != '_':
                    cnameAddr = cnameAddr + '.'
                else:
                    cnameAddr = cnameAddr + chr(ys)
        return cnameAddr

    def naptrResInfo(self):
        naptrinfo = ''
        flags = ''
        service = ''
        regex = ''
        self.naptrIndex = int.from_bytes(self.res[self.answerStart + self.answerNode + 10:self.answerStart + self.answerNode + 12],byteorder='big', signed=False)
        order = int.from_bytes(self.res[self.answerStart + self.answerNode + 12:self.answerStart + self.answerNode + 14],byteorder='big', signed=False)
        naptrinfo = naptrinfo + str(order)
        preference = int.from_bytes(self.res[self.answerStart + self.answerNode + 14:self.answerStart + self.answerNode + 16],byteorder='big', signed=False)
        naptrinfo = naptrinfo + ' ' + str(preference)
        flaglenth = int.from_bytes(self.res[self.answerStart + self.answerNode + 16:self.answerStart + self.answerNode + 17],byteorder='big', signed=False)
        for i in self.res[self.answerStart + self.answerNode + 17:self.answerStart + self.answerNode + 17 + flaglenth]:
            flags = flags + chr(i)
        servicelenth = int.from_bytes(self.res[self.answerStart + self.answerNode + 17 + flaglenth:self.answerStart + self.answerNode + 18 + flaglenth],byteorder='big', signed=False)
        for i in self.res[self.answerStart + self.answerNode + 18 + flaglenth:self.answerStart + self.answerNode + 18 + flaglenth + servicelenth]:
            service = service + chr(i)
        regexlenth = int.from_bytes(self.res[self.answerStart + self.answerNode + 18 + flaglenth + servicelenth:self.answerStart + self.answerNode + 19 + flaglenth + servicelenth],byteorder='big', signed=False)
        for i in self.res[self.answerStart + self.answerNode + 19 + flaglenth + servicelenth:self.answerStart + self.answerNode + 19 + flaglenth + servicelenth + regexlenth]:
            regex = regex + chr(i)
        self.naptrStartIndex = 19 + flaglenth + servicelenth + regexlenth
        return naptrinfo, flags, service, regex

    def txtResAddr(self):
        txtlenth = 0
        node = 0
        txtaddrtmp = ''
        txtaddr = ''
        txtdatalenth = int.from_bytes(self.res[self.answerStart + self.answerNode + 10:self.answerStart + self.answerNode + 12],byteorder='big', signed=False)
        while True:
            if txtlenth != txtdatalenth:
                for j in range(int.from_bytes(self.res[self.answerStart + self.answerNode + 12 + node:self.answerStart + self.answerNode + 13 + node],byteorder='big', signed=False)):
                    txtaddrtmp = txtaddrtmp + str(self.res[self.answerStart + self.answerNode + 13 + node + j:self.answerStart + self.answerNode + 14 + node + j],encoding="utf-8")
                txtaddr = txtaddr + '"%s"' % txtaddrtmp + ' '
                txtaddrtmp = ''
                txtlenth = txtlenth + int.from_bytes(self.res[self.answerStart + self.answerNode + 12 + node:self.answerStart + self.answerNode + 13 + node],byteorder='big', signed=False) + 1
                node = txtlenth
            else:
                return txtaddr

    def spfResAddr(self):
        spfAddr = ''
        self.spfIndex = int.from_bytes(self.res[self.answerStart + self.answerNode + 10:self.answerStart + self.answerNode + 12],byteorder='big', signed=False)
        for i in range(int.from_bytes(self.res[self.answerStart + self.answerNode + 12:self.answerStart + self.answerNode + 13],byteorder='big', signed=False)):
            spfAddr = spfAddr + str(self.res[self.answerStart + self.answerNode + 13 + i:self.answerStart + self.answerNode + 14 + i],encoding="utf-8")
        spfAddr = '"' + spfAddr + '"'
        return spfAddr

    def caaResAddr(self):
        caaAddr = ''
        tag = ''
        value = ''
        self.caaIndex = int.from_bytes(self.res[self.answerStart + self.answerNode + 10:self.answerStart + self.answerNode + 12],byteorder='big', signed=False)
        caaFlag = str(int.from_bytes(self.res[self.answerStart + self.answerNode + 12:self.answerStart + self.answerNode + 13],byteorder='big', signed=False))
        for i in range(int.from_bytes(self.res[self.answerStart + self.answerNode + 13:self.answerStart + self.answerNode + 14],byteorder='big', signed=False)):
            tag = tag + str(self.res[self.answerStart + self.answerNode + 14 + i:self.answerStart + self.answerNode + 15 + i],encoding="utf-8")
        for j in range(self.caaIndex - 2 - int.from_bytes(self.res[self.answerStart + self.answerNode + 13:self.answerStart + self.answerNode + 14],byteorder='big', signed=False)):
            value = value + str(self.res[self.answerStart + self.answerNode + 14 + int.from_bytes(self.res[self.answerStart + self.answerNode + 13:self.answerStart + self.answerNode + 14],byteorder='big', signed=False)+ j:self.answerStart + self.answerNode + 15 + int.from_bytes(self.res[self.answerStart + self.answerNode + 13:self.answerStart + self.answerNode + 14],byteorder='big', signed=False) + j],encoding="utf-8")
        caaAddr = caaAddr + caaFlag + ' ' + tag + ' "' + value + '"'
        return caaAddr

    def dnsClient(self):
        if self.domain[-1] != '.':
            self.domain = self.domain + '.'
        if self.pro == 'tcp':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.server, self.port))
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(self.timeout)
        if self.opt == 'dup':
            id = 1234
        else:
            id = random.randint(0, 65535)
        if self.opt == 'qrerr':
            udp_flag = 8120
        else:
            udp_flag = 288
        udp_question = 1
        if self.opt == 'msgerr':
            udp_AnswerRrs = 1
        else:
            udp_AnswerRrs = 0
        udp_AuthorityRrs = 0
        udp_AdditionalRrs = 0
        domainLen = b''
        self.domainType = ''
        for i in self.domain.split('.'):
            domainLen = domainLen + struct.pack('!b', len(i)) + i.encode('ascii')
        for k, v in typeDict.items():
            if v == self.queryType:
                self.domainType = k
        if self.opt == 'classerr':
            queryClass = 0
        else:
            queryClass = 1
        msg = struct.pack('!6H%ds2H' % len(domainLen), id, udp_flag, udp_question, udp_AnswerRrs, udp_AuthorityRrs, udp_AdditionalRrs, domainLen, self.domainType, queryClass)
        # print(msg)
        self.starttime = time.time()
        if self.opt == None:
            if self.pro == 'udp':
                s.sendto(msg, (self.server, self.port))
            else:
                s.send(struct.pack('!1H', len(msg)) + msg)
        elif self.opt== 'dup':
            if self.pro == 'udp':
                s.sendto(msg, (self.server, self.port))
                s.sendto(msg, (self.server, self.port))
            else:
                s.send(struct.pack('!1H', len(msg)) + msg)
                s.send(struct.pack('!1H', len(msg)) + msg)
        elif self.opt == 'headerr':
            msg = struct.pack('!5H%ds2H' % len(domainLen), udp_flag, udp_question, udp_AnswerRrs, udp_AuthorityRrs, udp_AdditionalRrs, domainLen, self.domainType, queryClass)
            if self.pro == 'udp':
                s.sendto(msg, (self.server, self.port))
            else:
                s.send(struct.pack('!1H', len(msg)) + msg)
        elif self.opt == 'qnameerr':
            msg = struct.pack('!6H2H', id, udp_flag, udp_question, udp_AnswerRrs, udp_AuthorityRrs, udp_AdditionalRrs, self.domainType, queryClass)
            if self.pro == 'udp':
                s.sendto(msg, (self.server, self.port))
            else:
                s.send(struct.pack('!1H', len(msg)) + msg)
        try:
            c = s.recv(4096)
        except socket.timeout:
            return 'timeout'
        self.endtime = time.time()
        # print(c)
        s.close()
        return c

    def dnsResponse(self):
        try:
            self.res = self.dnsClient()
            assert self.res != 'timeout' and self.res != b''
        except Exception:
            return print('========Request timeout========')
        except KeyboardInterrupt:
            return print('========Break Request========')
        if self.pro == 'udp':
            self.res = self.res
        else:
            self.res = self.res[2:]
        domainEnd = 12 + len(self.domain) + 1
        self.answerStart = 12 + len(self.domain) + 5
        domainNameTmp = str(self.res[12:domainEnd].decode())
        domainName = ''
        recordes = recodesDict[int(bin(int.from_bytes(self.res[3:4], byteorder='big', signed=False))[-4:], 2)]
        for i in domainNameTmp:
            if i not in str(self.res):
                i = '.'
            domainName = domainName + i
        # print(int.from_bytes(b'\x0c', byteorder='big', signed=False))
        if bin(int.from_bytes(self.res[2:4], byteorder='big', signed=False))[2:3] == '1':
            QR = 'response'
        else:
            QR = 'query'
        if str(bin(int.from_bytes(self.res[2:4], byteorder='big', signed=False))[3:7]) == '0000':
            opcode = 'standard'
        elif str(bin(int.from_bytes(self.res[2:4], byteorder='big', signed=False))[3:7]) == '0001':
            opcode = 'reverse'
        elif str(bin(int.from_bytes(self.res[2:4], byteorder='big', signed=False))[3:7]) == '0010':
            opcode = 'status'
        else:
            opcode = None
        flagBit = ''
        if bin(int.from_bytes(self.res[2:4], byteorder='big', signed=False))[7:8] == '1':
            flagBit = flagBit + 'AA' + ' '
        if bin(int.from_bytes(self.res[2:4], byteorder='big', signed=False))[8:9] == '1':
            flagBit = flagBit + 'TC' + ' '
        if bin(int.from_bytes(self.res[2:4], byteorder='big', signed=False))[9:10] == '1':
            flagBit = flagBit + 'RD' + ' '
        if bin(int.from_bytes(self.res[2:4], byteorder='big', signed=False))[10:11] == '1':
            flagBit = flagBit + 'RA'

        print('\nId:', int.from_bytes(self.res[:2], byteorder='big', signed=False), QR, opcode, flagBit, 'Questions:', int.from_bytes(self.res[4:6], byteorder='big', signed=False), recordes)
        print('Answer num:', int.from_bytes(self.res[6:8], byteorder='big', signed=False))
        print('Authority num:', int.from_bytes(self.res[8:10], byteorder='big', signed=False))
        print('Additional num:', int.from_bytes(self.res[10:12], byteorder='big', signed=False))
        print('Domain:', domainName[1:], 'Type:', typeDict[self.domainType])
        print('\nAnswer:')
        self.answerNode = 0
        # data lenth c[answerStart+10:answerStart+12]
        for i in range(int.from_bytes(self.res[6:8], byteorder='big', signed=False)):
            if int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4], byteorder='big', signed=False) == 5:
                cnameInfo = self.cnameResAddr()
                cnameTmp = self.domainResName()
                print('{0:25}\t{1:<10d}'.format(cnameTmp, int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big',signed=False)],'\t',cnameInfo)
                self.answerNode = 12 + self.answerIndex + self.answerNode
            elif int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 1:
                ipaddr = self.aRes()
                cnameName = self.domainResName()
                print('{0:25}\t{1:<10d}'.format(cnameName or self.domain,int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)), 'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t', ipaddr)
                self.answerNode = self.answerNode + 16
            elif int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 28:
                aaaaName = self.domainResName()
                aaaaipaddr = self.aaaaRes()
                print('{0:25}\t{1:<10d}'.format(aaaaName,int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t', aaaaipaddr)
                self.answerNode = self.answerNode + 28
            elif int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 2:
                nsName = self.domainResName()
                nsAddr = self.nsRes(12)
                print('{0:25}\t{1:<10d}'.format(nsName,int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t',nsAddr)
                self.answerNode = self.answerNode + self.nsIndex + 12
            elif int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 15:
                mxName = self.domainResName()
                mxAddr = self.nsRes(14)
                print('{0:25}\t{1:<10d}'.format(mxName,int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t',int.from_bytes(self.res[self.answerStart + self.answerNode + 12:self.answerStart + self.answerNode + 14],byteorder='big', signed=False),mxAddr)
                self.answerNode = self.answerNode + self.nsIndex + 14
            elif int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 35:
                naptrName = self.domainResName()
                naptrInfo = self.naptrResInfo()
                naptrAddr = self.nsRes(self.naptrStartIndex)
                print('{0:25}\t{1:<10d}'.format(naptrName,int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t',naptrInfo[0],'"%s" "%s" "%s"' % (naptrInfo[1],naptrInfo[2],naptrInfo[3]),naptrAddr)
                self.answerNode = self.naptrIndex + 12
            elif int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 33:
                srvName = self.domainResName()
                srvAddr = self.nsRes(18)
                print('{0:25}\t{1:<10d}'.format(srvName,int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t',int.from_bytes(self.res[self.answerStart + self.answerNode + 12:self.answerStart + self.answerNode + 14],byteorder='big', signed=False),int.from_bytes(self.res[self.answerStart + self.answerNode + 14:self.answerStart + self.answerNode + 16],byteorder='big', signed=False),int.from_bytes(self.res[self.answerStart + self.answerNode + 16:self.answerStart + self.answerNode + 18],byteorder='big', signed=False),srvAddr)
                self.answerNode = self.answerNode + 12 + int.from_bytes(self.res[self.answerStart + self.answerNode + 10:self.answerStart + self.answerNode + 12], byteorder='big', signed=False)
            elif int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 12:
                ptrName = self.domainResName()
                ptrAddr = self.nsRes(12)
                print('{0:25}\t{1:<10d}'.format(ptrName,int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t',ptrAddr)
                self.answerNode = self.answerNode + 12 + int.from_bytes(self.res[self.answerStart + self.answerNode + 10:self.answerStart + self.answerNode + 12],byteorder='big', signed=False)
            elif int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 16:
                txtName = self.domainResName()
                txtAddr = self.txtResAddr()
                print('{0:25}\t{1:<10d}'.format(txtName,int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t',txtAddr)
                self.answerNode = self.answerNode + 12 + int.from_bytes(self.res[self.answerStart + self.answerNode + 10:self.answerStart + self.answerNode + 12],byteorder='big', signed=False)
            elif int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 39:
                dnameName = self.domainResName()
                dnameAddr = self.nsRes(12)
                print('{0:25}\t{1:<10d}'.format(dnameName,int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t',dnameAddr)
                self.answerNode = self.answerNode + self.nsIndex + 12
            elif int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 99:
                spfName = self.domainResName()
                spfAddr = self.spfResAddr()
                print('{0:25}\t{1:<10d}'.format(spfName,int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t',spfAddr)
                self.answerNode = self.answerNode + self.spfIndex + 12
            elif int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 257:
                caaName = self.domainResName()
                caaAddr = self.caaResAddr()
                print('{0:25}\t{1:<10d}'.format(caaName,int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t',caaAddr)
                self.answerNode = self.answerNode + self.caaIndex + 12

        print('\nAuthority Nameservers:')
        self.nsStartIndex = self.answerStart + self.answerNode
        for auth in range(int.from_bytes(self.res[8:10], byteorder='big', signed=False)):
            domainNs = self.compression(self.res[self.nsStartIndex:self.nsStartIndex + 2])
            if int.from_bytes(self.res[self.nsStartIndex:self.nsStartIndex + 1], byteorder='big', signed=False) == 0:
                nsDomain = self.nsRes(11)
                print('{0:25}\t{1:<10d}'.format('.', int.from_bytes(self.res[self.answerStart + self.answerNode + 5:self.answerStart + self.answerNode + 9],byteorder='big', signed=False)), 'IN', '\t', typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 1:self.answerStart + self.answerNode + 3],byteorder='big', signed=False)],'\t',nsDomain)
                self.answerNode = self.answerNode + 11 + self.nsIndex
            else:
                nsDomain = self.nsRes(12)
                print('{0:25}\t{1:<10d}'.format(domainNs, int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4], byteorder='big', signed=False)],'\t',nsDomain)
                self.answerNode = self.answerNode + 12 + self.nsIndex

        print('\nAdditional Records:')
        for record in range(int.from_bytes(self.res[10:12], byteorder='big', signed=False)):
            if int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 1:
                recordName = self.domainResName()
                aRecord = self.aRes()
                print('{0:25}\t{1:<10d}'.format(recordName, int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t', aRecord)
                self.answerNode = self.answerNode + 16
            if int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False) == 28:
                recordName = self.domainResName()
                aaaaRecord = self.aaaaRes()
                print('{0:25}\t{1:<10d}'.format(recordName, int.from_bytes(self.res[self.answerStart + self.answerNode + 6:self.answerStart + self.answerNode + 10],byteorder='big', signed=False)),'IN','\t',typeDict[int.from_bytes(self.res[self.answerStart + self.answerNode + 2:self.answerStart + self.answerNode + 4],byteorder='big', signed=False)],'\t', aaaaRecord)
                self.answerNode = self.answerNode + 28

        print('\nQuery time:', '%.2f' % ((self.endtime - self.starttime)*1000), 'ms')

def main():
    parser = optparse.OptionParser()
    parser.add_option("-d", "--domain", dest = "domain", help = "Request domainname", metavar= "xxx.xxx.xxx")
    parser.add_option("-s", "--server", dest = "server", help = "DNS server to Request", metavar = "default 127.0.0.1", default = "127.0.0.1")
    parser.add_option("-p", "--port", dest = "port", type = "int", help = "Request Port", metavar = "default 53", default = 53)
    parser.add_option("-t", "--rtype", dest = "type", help = "Request q-type", metavar = "default A", default = "A")
    parser.add_option("-o", "--option", dest = "opt", help = "Request error options", metavar = "dup(duplicate), headerr(headerror), qrerr(qrerror),msgerr(messageerror),classerr(classerror), qnameerr(qnameerror), default None\n", default = None)
    parser.add_option("-i", "--timeout", dest = "timeout", type = "int", help = "Set Request timeout", metavar = "10  default 10", default = 10)
    parser.add_option("-z", "--protocol", dest = "pro", help = "Set Request Protocol", metavar = "udp, tcp default udp", default = "udp")
    (options, args) = parser.parse_args()
    if len(options.server.split('.')) != 4:
        parser.error("invalid ipaddress")
    for i in options.server.split('.'):
        try:
            i = int(i)
        except Exception:
            return parser.error("invalid ipaddress")
        if i < 0 or i > 255:
            parser.error("invalid ipaddress")
        if options.type.upper() not in typeDict.values():
            return parser.error("invalid qtype")
        if options.pro.lower() != 'udp' and options.pro.lower() != 'tcp':
            return parser.error("invalid protocol")
        if options.opt != None:
            if options.opt.lower() != 'dup' and options.opt.lower() != 'headerr' and options.opt.lower() != 'qrerr' and options.opt.lower() != 'msgerr' and options.opt.lower() != 'classerr' and options.opt.lower() != 'qnameerr':
                return parser.error("invalid error options params")
    dig = PythonDig(domain = options.domain, server = options.server, port = options.port, opt = options.opt, queryType = options.type, timeout = options.timeout, pro = options.pro)
    dig.dnsResponse()

if __name__ == '__main__':
    main()
