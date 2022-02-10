import sys
import ipaddress
import os
import uuid

listVdomObjects = []
listInterfaceZoneMap = []
listAddressObjects = []
listAddressGroupObjects = []
listServicesObjects = []
listServicesGroupObjects = []
listVirtualIPObjects = []
listVIPGroupObjects = []
listIPpoolObjects = []
listIPSECTunnel = []
listRouteObjects = []
listPolicyObjects = []
listZoneObjects = []

fgtconf = ''
intmap = ''
gvdom = 'root'
vdomMode = 'disabled'

for param in sys.argv :
    #xgconfig.write(param)
    if '--fgtconf' in param:
        fgtconf = param.replace("--fgtconf=","")
        #xgconfig.write(filepath)
    if '--intmap' in param:
        intmap = param.replace("--intmap=","")
        #xgconfig.write(filepath)
        
xgconfig = open("Entities.xml", "w")
#flog = open(fgtconf + ".log", "w")
#fcompare = open(fgtconf + ".cmp", "w") 

class InterfaceZoneMap:
    def __init__(self, fgtint, fgtips, fgtintftype, fgtvlanid, fgtintvlanlag, fgtvdom, xgintname, xgintips, xginttype, xgvlanid, xgintvlanlag, xgzone, description):  
        self.fgtint = fgtint
        self.fgtips = fgtips
        self.fgtintftype = fgtintftype 
        self.fgtvlanid = fgtvlanid
        self.fgtintvlanlag = fgtintvlanlag
        self.fgtvdom = fgtvdom
        self.xgintname = xgintname
        self.xgintips = xgintips
        self.xginttype = xginttype
        self.xgvlanid = xgvlanid
        self.xgintvlanlag = xgintvlanlag 
        self.xgzone = xgzone
        self.description = description
        
class InterfaceZone:
    def __init__(self, name, interfaces, intrazones):
        self.name = name
        self.interfaces = interfaces
        self.intrazones = intrazones
        
class IPSECTunnel:
    def __init__(self, name, interface, remotegateway, localid, remoteid, psk):
        self.name = name
        self.interface = interface
        self.remotegateway = remotegateway
        self.localid = localid
        self.remoteid = remoteid
        self.psk = psk
        
class Address:  
    def __init__(self, name, hosttype, ip, ipmask, startip, endip, fqdn, description):  
        self.name = name  
        self.hosttype = hosttype
        self.ip = ip
        self.ipmask = ipmask
        self.startip = startip
        self.endip = endip
        self.fqdn = fqdn
        self.description = description
        
class AddressGroup:  
    def __init__(self, name, members,description):  
        self.name = name  
        self.members = members
        self.description = description
        
class Service:  
    def __init__(self, name, srvtype, tcprange, udprange, description):  
        self.name = name
        self.srvtype = srvtype
        self.tcprange = tcprange
        self.udprange = udprange
        self.description = description

class ServiceGroup:  
    def __init__(self, name, members,description):  
        self.name = name  
        self.members = members
        self.description = description
        
#verificar loadbalance
class VirtualIP:
    def __init__(self, name, viptype, extip, extintf, mappedip, realservers, description):  
        self.name = name
        self.viptype = viptype
        self.extip = extip
        self.extintf = extintf
        self.mappedip = mappedip
        self.realservers = realservers
        self.description = description 
        
class VIPGroup:  
    def __init__(self, name, members,description):  
        self.name = name  
        self.members = members
        self.description = description

class IPpool:
    def __init__(self, name, startip, endip, description):  
        self.name = name
        self.startip = startip 
        self.endip = endip
        self.description = description 
    
class Route:
    def __init__(self, routerid, netdst, netmask, gateway, device, distance, priority, routetype, description):  
        self.routerid = routerid
        self.netdst = netdst
        self.netmask = netmask
        self.gateway = gateway
        self.device = device
        self.distance = distance
        self.priority = priority
        self.routetype = routetype
        self.description = description
        
class Policy:
    def __init__(self, policyid, policytype, name, uuid, srcintf, dstintf, srcaddr, dstaddr, action, status, schedule, service, logtraffic, users, groups, nat, ippool, ippoolnames, ipssensor, avprofile, webfilterprofile, applicationlist, sslsshprofile, description):  
        self.policyid = policyid
        self.policytype = policytype
        self.name = name
        self.uuid = uuid
        self.srcintf = srcintf
        self.dstintf = dstintf
        self.srcaddr = srcaddr
        self.dstaddr = dstaddr
        self.action = action
        self.status = status
        self.schedule = schedule
        self.service = service
        self.logtraffic = logtraffic
        self.groups = groups
        self.users = users
        self.nat = nat
        self.ippool = ippool
        self.ippoolnames = ippoolnames
        self.ipssensor = ipssensor 
        self.avprofile = avprofile
        self.webfilterprofile = webfilterprofile
        self.applicationlist = applicationlist
        self.sslsshprofile = sslsshprofile
        self.description = description
                
def getListVDOM(f):
   
    stop = 'end'
    
    line = f.readline()
    
    if len(listVdomObjects) < 1:
        global vdomMode
        vdomMode = 'enabled'
    
        while line:
            line = line.strip()
            
            if 'edit' in line:
                vdom = line.replace("edit ","")
                listVdomObjects.append(vdom)
            
            if  line == stop:
                break
                
            line = f.readline()   
    else:   
        #com lista de vdom comprara com existente e grava
        line = line.strip()
        
        for vdom in listVdomObjects:
            line = line.replace("edit ","")
            
            if vdom == line:
                global gvdom 
                global xgconfig
                
                #pula a vdom root para gravar no arquivo sendo a vdom root como primeira
                if vdom != 'root':
                    #grava a atual vdom no arquivo vdom  Entities_xml
                    printObjects()
                    clearObjects()
                
                gvdom = line
                xgconfig = open("Entities_"+ gvdom +".xml", "w")
                

    
def getListZones(f):
    stop = 'end'
    name = ''
    interfaces = ''
    intrazones = ''
    
    line = f.readline()
    
    while line:
        
        line = line.strip()
        
        if 'edit' in line:
            aname = line.replace("edit \"","")
            name = aname.replace("\"","")
            name = trataInterfaceZone(name)
            
        if 'set interface' in line:
            memberline = line.replace("set interface ", "")
            memberline = memberline.replace("\" \"",",")
            strmember = memberline.replace("\"","")
            # tratando string
            interfaces = trataString(strmember)
            
        if 'set intrazone' in line:
            intrazones = line.replace("set intrazone ","")
            intrazones = intrazones.replace("\"","")                   
        
        if line=='next':
            listZoneObjects.append(InterfaceZone(name,interfaces,intrazones))
                        
        if  line == stop:
            break
            
        line = f.readline()
    
    
    
def getListAddress(f):
    stop = 'end'
    
    hosttype = ''
    ip = ''
    ipmask = ''
    startip = ''
    endip = ''
    fqdn = ''
    description = 'Sophos Migration Tool'
    
    line = f.readline()   
        
    while line:

        
        line = line.strip()

        if 'edit' in line:
            aname = line.replace("edit \"","")
            name = aname.replace("\"","")
            name = trataString(name)
            
        if 'set subnet' in line:
            subnet = line.replace("set subnet ","")
            splitsubnet = subnet.split()
            
            if splitsubnet[1] == '255.255.255.255':
                hosttype = 'IP'
                ip = splitsubnet[0]
                ipmask = splitsubnet[1]
                
                #listAddressObjects.append(Address(name,hosttype,ip,ipmask,'','','',description))
            
            else:
                hosttype = 'Network'
                ip = splitsubnet[0]
                ipmask = splitsubnet[1]
                
                #listAddressObjects.append(Address(name,hosttype,ip,ipmask,'','','',description))
        
        if 'set type iprange' in line:
            hosttype = 'IPRange'

        if 'set start' in line:
            startip = line.replace("set start-ip ","")
        
        if 'set end' in line:
            endip = line.replace("set end-ip ","")
                
            #listAddressObjects.append(Address(name,hosttype,'','',startip,endip,'',description))

                       
        if 'set wildcard-fqdn' in line:
            fqdn = line.replace("set wildcard-fqdn \"","")
            fqdn = fqdn.replace("\"","")
            fqdn = trataFQDN(fqdn)
            
            hosttype = 'FQDNHost'
            
            #listAddressObjects.append(Address(name,hosttype,'','','','',fqdn,description))
       
        if 'set fqdn' in line:
            fqdn = line.replace("set fqdn \"","")
            fqdn = fqdn.replace("\"","")
            fqdn = trataFQDN(fqdn)
            
            hosttype = 'FQDNHost'
            
            #listAddressObjects.append(Address(name,hosttype,'','','','',fqdn,description))
            
        if line=='next':
            listAddressObjects.append(Address(name, hosttype, ip, ipmask, startip, endip, fqdn, description))
            
            hosttype = ''
            ip = ''
            ipmask = ''
            startip = ''
            endip = ''
            fqdn = ''
            description = 'Sophos Migration Tool'

        if line==stop:
            break
        
        line = f.readline()
        
        
def getListAddressGroup(f):
    stop = 'end'
    name = ''
    strmember = ''
    description = ''
    
    line = f.readline()
    
    while line:
        line = line.strip()

        if 'edit' in line:
            aname = line.replace("edit \"","")
            name = aname.replace("\"","")
            name = trataString(name)
            
        if 'set member' in line:
            memberline = line.replace("set member ", "")
            memberline = memberline.replace("\" \"",",")
            strmember = memberline.replace("\"","")
            # tratando string
            strmember = trataString(strmember)
            
            #for addr in strmember.split(","):
                #isAddress(addr)
        
        if 'set comment' in line:
            acomment = line.replace("set comment \"","")
            description = acomment.replace("\"","")

        if line=='next':
            listAddressGroupObjects.append(AddressGroup(name,strmember,description))
               
            name = ''
            strmember = ''
            description = ''
            
        if line==stop:
            break
        
        line = f.readline()
        
def getListService(f):
    #TODO implementar IP ICMP 

    """   
    <Services>
    <Name>Name</Name>
    <Type>TCPorUDP/IP/ICMP/ICMPv6</Type>
    <ServiceDetails>
    <ServiceDetail>
    <!-- for TCPUDP type -->
    <Protocol>TCP/UDP</Protocol>
    <SourcePort>port</SourcePort>
    <DestinationPort>port</DestinationPort>
    <!-- for IP type -->
    <ProtocolName>HOPOPT/ICMP/IGMPGGP/IP/ST/TCP/CBT/EGP/IGP/BBN-RCC-MON/NVP-II/PUP/ARGUS/EMCON/XNET/CHAOS/UDP/MUX/DCN-MEAS/HMP/PRM/XNS-IDP/TRUNK-1/TRUNK-2/LEAF-1/LEAF-2/RDP/IRTP/ISO-TP4/NETBLT/MFE-NSP/MERIT-INP/DCCP/3PC/IDPRXTP/DDP/IDPR-CMTP/TP++/IL/IPv6/SDRP/IPv6-Route/IPv6-Frag/IDRP/RSVP/GRE/DSR/BNA/ESP/AH/I-NLSP/SWIPE/NARP/MOBILE/TLSP/SKIP/IPv6-ICMP/IPv6-NoNxt/IPv6-Opts/IPProto61/CFTP/IPProto63/SAT-EXPAK/KRYPTOLAN/RVD/IPPC/IPProto68/SAT-MON/VISA/IPCV/CPNX/CPHB/WSN/PVP/BR-SAT-MON/SUN-ND/WB-MON/WB-EXPAK/ISO-IP/VMTP/SECURE-VMTP/VINES/TTP/NSFNET-IGP/DGP/TCF/EIGRP/OSPFIGP/Sprite-RPC/LARP/MTP/25/IPIP/MICP/SCC-SP/ETHERIP/ENCAP/IPProto99/GMTP/IFMP/PNNI/PIM/ARIS/SCPS/QNX/A/N/IPComp/SNP/Compaq-Peer/IPX-in-IP/VRRP/PGM/IPProto114/L2TP/DDX/IATP/STP/SRP/UTI/SMP/SM/PTP/ISIS/FIRE/CRTP/CRUDP/SSCOPMCE/IPLT/SPS/PIPE/SCTP/FC/RSVP-E2E-IGNORE/IPProto135/UDPLite/MPLS-in-IP/manet/HIP/Shim6/WESP/ 
    ROHC/IPProto143/IPProto144/IPProto145/IPProto146/IPProto147/IPProto148/IPProto149/IPProto150/IPProto151/IPProto152/IPProto153/IPProto154/IPProto155/IPProto156/IPProto157/IPProto158/IPProto159/IPProto160/IPProto161/IPProto162/IPProto163/IPProto164/IPProto165/IPProto166/IPProto167/IPProto168/IPProto169/IPProto170/IPProto171/IPProto172/IPProto173/IPProto174/IPProto175/IPProto176/IPProto177/IPProto178/IPProto179/IPProto180/IPProto181/IPProto182/IPProto183/IPProto184/IPProto185/IPProto186/IPProto187/IPProto188/IPProto189/IPProto190/IPProto191/IPProto192/IPProto193/IPProto194/IPProto195/IPProto196/IPProto197/IPProto198/IPProto199/IPProto200/IPProto201/IPProto202/IPProto203/IPProto204/IPProto205/IPProto206/IPProto207/IPProto208/IPProto209/IPProto210/IPProto211/IPProto212/IPProto213/IPProto214/IPProto215/IPProto216/IPProto217/IPProto218/IPProto219/IPProto220/IPProto221/     
    IPProto222/IPProto223/IPProto224/IPProto225/IPProto226/IPProto227/IPProto228/IPProto229/IPProto230/IPProto231/IPProto232/IPProto233/IPProto234/IPProto235/IPProto236/IPProto237/IPProto238/IPProto239/IPProto240/IPProto241/IPProto242/IPProto243/IPProto244/IPProto245/IPProto246/IPProto247/IPProto248/IPProto249/IPProto250/IPProto251/IPProto252/IPProto253/IPProto254/IPProto255</ProtocolName>
    <!-- for ICMP Type -->
    <ICMPType>Echo Reply/Destination Unreachable/Source Quench/Redirect/Alternate Host Address/Echo/Router Advertisement/Router Selection/Time Exceeded/Parameter Problem/Timestamp/Timestamp Reply/Information Request/Information Reply/Address Mask Request/Address Mask Reply/Traceroute/Datagram Conversion Error/Mobile Host Redirect/IPv6 Where-Are-You/IPv6 I-Am-Here/Mobile Registration Request/Mobile Registration Reply/Domain Name Request/Domain Name Reply/SKIP/Photuris/Any Type</ICMPType>
    <ICMPCode>any code</ICMPCode>
    <!-- for ICMP Type -->
    <ICMPv6Type>Destination Unreachable/Packet Too Big/Time Exceeded/Parameter Problem/Private experimentation/Private experimentation/Echo Request/Echo Reply/Multicast Listener Query/Multicast Listener Report/Multicast Listener Done/Router Solicitation/Router Advertisement/Neighbor Solicitation/Neighbor Advertisement/Redirect Message/Router Renumbering/ICMP Node Information Query/ICMP Node Information Response/Inverse Neighbor Discovery Solicitation Message/Inverse Neighbor Discovery Advertisement Message/Version 2 Multicast Listener Report/Home Agent Address Discovery Request Message/Home Agent Address Discovery Reply Message/Mobile Prefix Solicitation/Mobile Prefix Advertisement/Certification Path Solicitation Message/Certification Path Advertisement Message/ICMP messages utilized by experimental mobility protocols such as Seamoby/Multicast Router Advertisement/Multicast Router Solicitation/Multicast Router Termination/FMIPv6 Messages/RPL Control Message/ILNPv6 Locator Update Message/Duplicate Address Request/Duplicate Address Confirmation/Private experimentation/Private experimentation/Any Type</ICMPv6Type>
    <ICMPv6Code>any code</ICMPv6Code>
    </ServiceDetail>
    :
    :
    </ServiceDetails>
    </Services>
    """
    
    name = ''
    srvtype = ''
    strtcprange = ''
    strudprange = ''
    description = ''
    
    stop = 'end'
    
    line = f.readline()
    
    while line:
        line = line.strip()

        if 'edit' in line:
            aname = line.replace("edit \"","")
            name = aname.replace("\"","")
            name = trataString(name)
            
        if 'set tcp-portrange' in line:
            rangeport = line.replace("set tcp-portrange ","")
            strtcprange = rangeport.replace(" ",",")
            #split by space list contain (dstportrange):(srcportrange)
            #splitedrangeport = rangeport.split()
            #tcprange = splitedrangeport.copy()
                        
        if 'set udp-portrange' in line:
            rangeport = line.replace("set udp-portrange ","")
            strudprange = rangeport.replace(" ",",")
            # split by space list contain (dstportrange):(srcportrange)
            #splitedrangeport = rangeport.split()
            #udprange = splitedrangeport.copy()

        if 'set comment' in line:
            #tratar caracteres especial no nome
            acomment = line.replace("set comment \"","")
            description = acomment.replace("\"","")
            
        if line=='next':

            srvtype = 'TCPorUDP'
            listServicesObjects.append(Service(name,srvtype,strtcprange,strudprange,description))

            name = ''
            srvtype = ''
            strtcprange = ''
            strudprange = ''
            description = ''

        if line==stop:
            break
        
        line = f.readline()
        
def getListServiceGroup(f):
    name = ''
    strmember = ''
    description = ''
    stop = 'end'
    
    line = f.readline()
    
    while line:
        line = line.strip()

        if 'edit' in line:
            aname = line.replace("edit \"","")
            name = aname.replace("\"","")
            name = trataString(name)
            
        if 'set member' in line:
            memberline = line.replace("set member ", "")
            memberline = memberline.replace("\" \"",",")
            strmember = memberline.replace("\"","")
            # tratando string
            strmember = trataString(strmember)
        
        if 'set comment' in line:
            acomment = line.replace("set comment \"","")
            description = acomment.replace("\"","")

        if line=='next':
            listServicesGroupObjects.append(ServiceGroup(name,strmember,description))
            
            name = ''
            strmember = ''
            description = ''
            
        if line==stop:
            break
        
        line = f.readline()
        
def getListVirtualIP(f):
    
    name = ''
    viptype = 'VirtualIP'
    extip = ''
    extintf = ''
    mappedip = ''
    realservers = ''
    description = ''
    
    stop = 'end'
    
    line = f.readline()    
    
    while line:
        line = line.strip()
       
        if 'edit "' in line:
            #tratar caracteres especial no nome
            aname = line.replace("edit \"","")
            name = aname.replace("\"","")
            name = trataString(name)
        
        if 'set comment' in line:
            acomment = line.replace("set comment \"","")
            description = acomment.replace("\"","")                
                        
        if 'set extip' in line:
            #tratar caracteres especial no nome
            aextip = line.replace("set extip ","")
            extip = aextip.replace("\"","")
        
        #verificar load balance ************************************
        if 'config realservers' in line:
            viptype = 'LoadBalance'
                       
            while 'end' not in line:
                
                line = line.strip()
                
                
                if 'edit' in line:
                    arealsrv = line.replace("edit ","")
                    realservers = realservers + 'server=' + arealsrv
                    
                if 'set ip' in line:
                    arealip = line.replace("set ip ","")
                    realservers = realservers + ',serverip=' + arealip
                       
                if 'set port' in line:
                    arealport = line.replace("set port ","")
                    realservers = realservers + ',serverport=' + arealport + ','
                   
                line = f.readline()              
                
        if 'set extintf' in line:
            aextintf = line.replace("set extintf \"","")
            extintf = aextintf.replace("\"","")
        
        if 'set mappedip' in line:
            amappedip = line.replace("set mappedip \"","")
            mappedip = amappedip.replace("\"","")
            
                
        if line=='next':
            listVirtualIPObjects.append(VirtualIP(name, viptype, extip, extintf, mappedip, realservers, description))
            name = ''
            viptype = 'VirtualIP'
            extip = ''
            extintf = ''
            mappedip = ''
            realservers = ''
            description = ''      

        if line==stop:
            break
        
        line = f.readline()
        
def getListVIPGroup(f):
    stop = 'end'
    name = ''
    strmember = ''
    description = ''
    
    line = f.readline()
    
    while line:
        line = line.strip()
       
        if 'edit' in line:
            aname = line.replace("edit \"","")
            name = aname.replace("\"","")
            name = trataString(name)
            
        if 'set member' in line:
            memberline = line.replace("set member ", "")
            memberline = memberline.replace("\" \"",",")
            strmember = memberline.replace("\"","")
            # tratando string
            strmember = trataString(strmember)

        
        if 'set comment' in line:
            acomment = line.replace("set comment \"","")
            description = acomment.replace("\"","")

        if line=='next':
            listVIPGroupObjects.append(VIPGroup(name,strmember,description))
               
            name = ''
            strmember = ''

            
        if line==stop:
            break
        
        line = f.readline()
        
def getListIPpool(f):
      
    name = ''
    startip = ''
    endip = ''
    description = ''
    
    stop = 'end'
    
    line = f.readline()
    
    while line:
        line = line.strip()
       
        if 'edit' in line:
            aname = line.replace("edit \"","")
            name = aname.replace("\"","")
            name = trataString(name)
       
        if 'set comment' in line:
            acomment = line.replace("set comments \"","")
            description = acomment.replace("\"","")
                   

        if 'set startip' in line:
            astartip = line.replace("set startip ","")
            startip = astartip.replace("\"","")
        
        if 'set endip' in line:
            aendip = line.replace("set endip ","")
            endip = aendip.replace("\"","")
        
        if line=='next':
            listIPpoolObjects.append(IPpool(name,startip,endip,description))
            name = ''
            startip = ''
            endip = ''
            description = ''       

        if line==stop:
            break
        
        line = f.readline()
        
def getListIPESCTunnel(f):
    name = '' 
    interface = '' 
    remotegateway = '' 
    localid = ''
    remoteid = ''
    psk = ''
    
    stop = 'end'
    
    line = f.readline()
    
    while line:
        line = line.strip()
       
        if 'edit' in line:
            aname = line.replace("edit \"","")
            name = aname.replace("\"","")
            name = trataString(name)
       
        if 'set interface' in line:
            interface = line.replace("set interface ","")
            interface = interface.replace("\"","")
        
        if 'set remote-gw' in line:
            remotegateway = line.replace("set remote-gw ","")
            remotegateway = remotegateway.replace("\"","")
            
        if 'set localid' in line:
            localid = line.replace("set localid \"","")
            localid = localid.replace("\"","")

        if 'set peerid' in line:
            remoteid = line.replace("set peerid \"","")
            remoteid = remoteid.replace("\"","")
            
        if 'set psksecret' in line:
            psk = line.replace("set psksecret \"","")
            psk = psk.replace("\"","")
        
        if line=='next':
            listIPSECTunnel.append(IPSECTunnel(name, interface, remotegateway, localid, remoteid, psk))
            name = '' 
            interface = '' 
            remotegateway = '' 
            localid = ''
            remoteid = ''
            psk = ''     

        if line==stop:
            break
        
        line = f.readline()
        
def getListRouterStatic(f):
    
    routerid = ''
    netdst = ''
    netmask = ''
    gateway = ''
    device = ''
    distance = '0'
    priority = '0'
    routetype = 'static'
    description = ''

    stop = 'end'

    line = f.readline()
    
    while line:
        line = line.strip()
        
        if 'edit' in line:
            anumber = line.replace("edit ","")
            routerid = anumber.replace("\"","")
                        
        if 'set dst' in line:
            dstline = line.replace("set dst ", "")
            dstline = dstline.replace("\"","")
            splitdst = dstline.split()
            netdst = splitdst[0]
            netmask = splitdst[1]
                                    
        if 'set gateway' in line:
            gateway = line.replace("set gateway ", "")
            gateway = gateway.replace("\"","")
                        
        if 'set device' in line:
            device = line.replace("set device ", "")
            device = device.replace("\"","")
            
        #8888888888888 implementar    
        if 'set distance' in line:
            distance = line.replace("set distance ", "")
            distance = device.replace("\"","")
                    
        #**********?????????????????//
        if 'set priority' in line:
            priority = line.replace("set priority ", "")
            priority = priority.replace("\"","")

        if 'set comment' in line:
            comment = line.replace("set comment ", "")
            description = comment.replace("\"","")
            
        if line=='next':
            if netdst == "":
                routetype = 'gateway'
            
            listRouteObjects.append(Route(routerid, netdst, netmask, gateway, device, distance, priority, routetype, description))

            routerid = ''
            netdst = ''
            netmask = ''
            gateway = ''
            device = ''
            distance = '0'
            priority = '0'
            routetype = 'static'
            description = ''
           
        if line==stop:
            break
        
        line = f.readline()

def getListPolicy(f):
    
    policyid = ''
    policytype = 'Firewall'
    name = ''
    uuid = ''
    srcintf = ''
    dstintf = ''
    srcaddr = ''
    dstaddr = ''
    action = 'drop' #Reject or Drop ??????????
    status = ''
    schedule = ''
    service = ''
    logtraffic = ''
    groups = ''
    users = ''    
    nat = 'disable'
    ippool = 'disable'
    ippoolnames = ''
    ipssensor = ''
    avprofile = ''
    webfilterprofile = ''
    #dlp-sensor ""
    applicationlist = ''
    #profile-protocol-options ""
    sslsshprofile = ''
    description = ''
     
    stop = 'end'
    
    line = f.readline()
    
    while line:
        line = line.strip()
        
        #FWv4.0 beta script
        if 'config identity-based-policy' in line:
            while line:
                line = line.strip()
                if 'set service' in line:
                    serviceline = line.replace("set service ", "")
                    serviceline = serviceline.replace("\" \"",",")
                    service = serviceline.replace("\"","")
                    #xgconfig.write("srv -> " + service)
                    
                if line == stop:
                    line = f.readline()
                    break
                line = f.readline()
                
        if 'edit ' in line:
            apolicyid = line.replace("edit ","")
            policyid = apolicyid.replace("\"","")
            
        if 'set name' in line:
            aname = line.replace("set name \"","")
            name = aname.replace("\"","")

        if 'set uuid' in line:
            auuid = line.replace("set uuid ","")
            uuid = auuid
            
        if 'set srcintf' in line:
            srcintfline = line.replace("set srcintf ", "")
            srcintfline = srcintfline.replace("\" \"",",")
            srcintf = srcintfline.replace("\"","")
            
            
        if 'set dstintf' in line:
            dstintfline = line.replace("set dstintf ", "")
            dstintfline = dstintfline.replace("\" \"",",")
            dstintf = dstintfline.replace("\"","")
            
        if 'set srcaddr' in line:
            srcaddrline = line.replace("set srcaddr ", "")
            srcaddrline = srcaddrline.replace("\" \"",",")
            srcaddr = srcaddrline.replace("\"","")
           
        if 'set dstaddr' in line:
            dstaddrline = line.replace("set dstaddr ", "")
            dstaddrline = dstaddrline.replace("\" \"",",")
            dstaddr = dstaddrline.replace("\"","")
            
            listdstaadr = dstaddr.split(",")
            
            for addr in listdstaadr:
                if isVIP(addr):
                    policytype = "VirtualIP"
                    
                    
                if isVipGroup(addr):
                    policytype = "VirtualIP"
                                  
            
        if 'set action' in line:
            aaction = line.replace("set action ","")
            action = aaction.replace("\"","")
            #xgconfig.write(action)
            
        if 'set status' in line:
            status = 'disable' #??????????
            #xgconfig.write(status)
    
        if 'set schedule' in line:
            aschedule = line.replace("set schedule \"","")
            schedule = aschedule.replace("\"","")
            #xgconfig.write(schedule)
            
        if 'set service' in line:
            serviceline = line.replace("set service ", "")
            serviceline = serviceline.replace("\" \"",",")
            service = serviceline.replace("\"","")
            #xgconfig.write("srv -> " + service)
            
        if 'set logtraffic' in line:
            alogtraffic = line.replace("set logtraffic ","")
            logtraffic = alogtraffic.replace("\"","")
            #xgconfig.write(logtraffic)
            
        if 'set groups' in line:
            groupsline = line.replace("set groups ", "")
            groupsline = groupsline.replace("\" \"",",")
            groups = groupsline.replace("\"","")
            #xgconfig.write('groups->' + groups)
            
        if 'set users' in line:
            usersline = line.replace("set users ", "")
            usersline = usersline.replace("\" \"",",")
            users = usersline.replace("\"","")
            #xgconfig.write('users-> ' + users)
        
        if 'set nat enable' in line:
            nat = 'enable'
            policytype = 'Masquerade'
        
        if 'set ippool enable' in line:
            ippool = 'enable'
            policytype = 'SNAT'
            
        if 'set poolname' in line:
            ippoolnamesline = line.replace("set poolname ", "")
            ippoolnamesline = ippoolnamesline.replace("\" \"",",")
            ippoolnames = ippoolnamesline.replace("\"","")
            
        if 'set ips-sensor' in line:
            ipssensor = line.replace("set ips-sensor ","")
            ipssensor = ipssensor.replace("\"","")
            
        if 'set av-profile' in line:
            avprofile = line.replace("set av-profile ","")
            avprofile = avprofile.replace("\"","")
            
        if 'set webfilter-profile' in line:
            webfilterprofile = line.replace("set webfilter-profile ","")
            webfilterprofile = webfilterprofile.replace("\"","")
        
        '''    
        if 'set dlp-sensor' in line:
            apolicyid = line.replace("edit ","")
            policyid = apolicyid.replace("\"","")
            
        if 'set profile-protocol-options' in line:
            apolicyid = line.replace("edit ","")
            policyid = apolicyid.replace("\"","")
        '''    
            
        if 'set application-list' in line:
            applicationlist = line.replace("set application-list ","")
            applicationlist = applicationlist.replace("\"","")

        if 'set ssl-ssh-profile' in line:
            sslsshprofile = line.replace("set ssl-ssh-profile ","")
            sslsshprofile = sslsshprofile.replace("\"","")
        
        if 'set comments' in line:
            comment = line.replace("set comments ", "")
            description = comment.replace("\"","")
        
            
        if line=='next':
            if uuid == '':                
                uuid = str(getUUID())
            
            listPolicyObjects.append(Policy(policyid, policytype, name, uuid, srcintf, dstintf, srcaddr, dstaddr, action, status, schedule, service, logtraffic, users, groups, nat, ippool, ippoolnames, ipssensor, avprofile, webfilterprofile, applicationlist, sslsshprofile, description))
                       
            policyid = ''
            policytype = 'Firewall'
            name = ''
            uuid = ''
            srcintf = ''
            dstintf = ''
            srcaddr = ''
            dstaddr = ''
            action = 'drop'
            status = 'enable'
            schedule = ''
            service = ''
            logtraffic = ''
            groups = ''
            users = ''
            description = ''
            nat = 'disable'
            ippool = 'disable'
            ippoolnames = ''
            ipssensor = ''
            avprofile = ''
            webfilterprofile = ''
            applicationlist = ''
            sslsshprofile = ''
            description = ''
                
        if line==stop:
            break
        
        line = f.readline()
    
def extractIPs(intIps):
    intIps = intIps.replace("[","")
    intIps = intIps.replace("]","")
    intIps = intIps.replace("p=","")
    intIps = intIps.replace("s=","")

    listip = intIps.split(";")
       
    return listip

def extractInterface(intfs):
    intfs = intfs.replace("[","")
    intfs = intfs.replace("]","")
    
    listintf = intfs.split(";")
    
    return listintf

def splitIpMask(ipMask):
    aux = ipMask.split("/")
        
    return aux

def getUUID():
    return uuid.uuid1()
  
def printAddress(listAddressObjects):
    """ implementar address de geolocalização """
    #fcompare.write("<IPHost>\n")
    
    for addr in listAddressObjects:
        #fcompare.write("<Name>"+addr.name+"</Name>\n")
        
        if addr.hosttype == 'IP':
            xgconfig.write("<IPHost>\n")
            xgconfig.write("<Name>"+addr.name+"</Name>\n")
            xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
            xgconfig.write("<HostType>IP</HostType>\n")
            xgconfig.write("<IPAddress>"+addr.ip+"</IPAddress>\n")
            xgconfig.write("</IPHost>\n")
            
        if addr.hosttype == 'Network':
            xgconfig.write("<IPHost>\n")
            xgconfig.write("<Name>"+addr.name+"</Name>\n")
            xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
            xgconfig.write("<HostType>Network</HostType>\n")
            xgconfig.write("<IPAddress>"+addr.ip+"</IPAddress>\n")
            xgconfig.write("<Subnet>"+addr.ipmask+"</Subnet>\n")
            xgconfig.write("</IPHost>\n")
        
        if addr.hosttype == 'IPRange':
            xgconfig.write("<IPHost>\n")
            xgconfig.write("<Name>"+addr.name+"</Name>\n")
            xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
            xgconfig.write("<HostType>IPRange</HostType>\n")
            xgconfig.write("<StartIPAddress>"+addr.startip+"</StartIPAddress>\n")
            xgconfig.write("<EndIPAddress>"+addr.endip+"</EndIPAddress>\n")
            xgconfig.write("</IPHost>\n")
        
    for vip in listVirtualIPObjects:
        #fcompare.write("<Name>"+vip.name+"</Name>\n")
        # IP Address Vip
        xgconfig.write("<IPHost>\n")
        xgconfig.write("<Name>"+vip.name+"</Name>\n")
        xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
        xgconfig.write("<HostType>IP</HostType>\n")
        xgconfig.write("<IPAddress>"+vip.extip+"</IPAddress>\n")
        xgconfig.write("</IPHost>\n")
        
        # IP externo
        xgconfig.write("<IPHost>\n")
        xgconfig.write("<Name>"+vip.name+"_EXT</Name>\n")
        xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
        xgconfig.write("<HostType>IP</HostType>\n")
        xgconfig.write("<IPAddress>"+vip.extip+"</IPAddress>\n")
        xgconfig.write("</IPHost>\n")
        
        # IP(s) interno(s)
        if vip.viptype == 'VirtualIP':
            xgconfig.write("<IPHost>\n")
            xgconfig.write("<Name>"+vip.name+"_INT</Name>\n")
            xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
            xgconfig.write("<HostType>IP</HostType>\n")
            xgconfig.write("<IPAddress>"+vip.mappedip+"</IPAddress>\n")
            xgconfig.write("</IPHost>\n")

        if vip.viptype == 'LoadBalance':
            number = ''
            srvip = ''
            
            realservers = vip.realservers.split(",")
                        
            for realsrv in realservers:                
                if 'server=' in realsrv:
                    number = realsrv.replace("server=","")
                    
                if 'serverip=' in realsrv:
                    srvip = realsrv.replace("serverip=","")                    
                    xgconfig.write("<IPHost>\n")
                    xgconfig.write("<Name>"+vip.name+"_INT"+number+"</Name>\n")
                    xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
                    xgconfig.write("<HostType>IP</HostType>\n")
                    xgconfig.write("<IPAddress>"+srvip+"</IPAddress>\n")
                    xgconfig.write("</IPHost>\n")
                    
                if 'serverport=' in realsrv:
                    log = "implementar"
                    
    for ippool in listIPpoolObjects:
        #fcompare.write("<Name>"+ippool.name+"</Name>\n")
        
        xgconfig.write("<IPHost>\n")
        xgconfig.write("<Name>"+ippool.name+"</Name>\n")
        xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
        xgconfig.write("<HostType>IPRange</HostType>\n")
        xgconfig.write("<StartIPAddress>"+ippool.startip+"</StartIPAddress>\n")
        xgconfig.write("<EndIPAddress>"+ippool.endip+"</EndIPAddress>\n")
        xgconfig.write("</IPHost>\n")        

    #fcompare.write("</IPHost>\n")
    
def printFQDN(listAddressGroupObjects):
    
    for addr in listAddressObjects:
        
        if addr.hosttype == 'FQDNHost':
            xgconfig.write("<FQDNHost>\n")
            xgconfig.write("<Name>"+addr.name+"</Name>\n")
            xgconfig.write("<FQDN>"+addr.fqdn+"</FQDN>\n")
            xgconfig.write("</FQDNHost>\n")
       
def printAddressGroup(listAddressGroupObjects):
    #fcompare.write("<IPHostGroup>\n")
    
    for addrgrp in listAddressGroupObjects:
        addrgrpname = trataString(addrgrp.name)
        
        #fcompare.write("<Name>"+addrgrpname+"</Name>\n")
        
        #flog.write("[INFO] AddressGroup=" + addrgrp.name + "\n")
        #flog.write("[INFO] AddressGroup=" + trataString(addrgrp.name) + " Tratado!\n")
        #flog.write("[INFO] Membros=" + addrgrp.members + "\n")
               
        xgconfig.write("<IPHostGroup>\n")
        xgconfig.write("<Name>"+addrgrpname+"</Name>\n")
        xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
        xgconfig.write("<Description>MigrationTool</Description>\n")
        xgconfig.write("<HostList>\n")
        
        listmembers = addrgrp.members.split(",")        

        for member in listmembers:
            address = findAddress(member)
            
            #grupo dentro de grupo expande os membros
            if address.name == 'null':
                
                addrgrpobj = findAddressGroup(member)
                
                listmembersgrp = addrgrpobj.members.split(",")
                
                for membergrp in listmembersgrp:
                    addressgrp = findAddress(membergrp)
                    
                    if addressgrp.hosttype != "FQDNHost":
                        addrname = trataString(addressgrp.name)
                        xgconfig.write("<Host>" + addrname + "</Host>\n")

            ##################################################################
            else:
                if address.hosttype != "FQDNHost":
                    addrname = trataString(address.name)
                    xgconfig.write("<Host>" + addrname + "</Host>\n")
                        
        xgconfig.write("</HostList>\n")
        xgconfig.write("</IPHostGroup>\n")
        
    #fcompare.write("<\IPHostGroup>\n")
        
def printFQDNGroup(listAddressGroupObjects):
    #fcompare.write("<FQDNHostGroup>\n")
    
    for fqdngrp in listAddressGroupObjects:
        fqdngrpname = trataString(fqdngrp.name) + "_grpfqdn"
        
        #fcompare.write("<Name>"+fqdngrpname+"</Name>\n")        
                  
        xgconfig.write("<FQDNHostGroup>\n")
        xgconfig.write("<Name>"+fqdngrpname+"</Name>\n")
        xgconfig.write("<Description>MigrationTool</Description>\n")
        xgconfig.write("<FQDNHostList>\n")
        
        listmembers = fqdngrp.members.split(",")        

        for member in listmembers:
                      
            for address in listAddressObjects:
                
                if address.name == member:

                    if address.hosttype == "FQDNHost":
                        #fcompare.write("<FQDNHost>" + trataString(address.name) + "</FQDNHost>\n")
                        
                        xgconfig.write("<FQDNHost>" + trataString(address.name) + "</FQDNHost>\n")
                        
        xgconfig.write("</FQDNHostList>\n")
        xgconfig.write("</FQDNHostGroup>\n")
        
    #fcompare.write("</FQDNHostGroup>\n")
        
def printServices(listServicesObjects):
    #fcompare.write("<Services>\n")
    
    for srv in listServicesObjects:
        srvname = trataString(srv.name)
        
        #fcompare.write("<Name>"+srvname+"</Name>\n")
  
        xgconfig.write("<Services>\n")
        xgconfig.write("<Name>"+srvname+"</Name>\n")
        xgconfig.write("<Type>TCPorUDP</Type>\n")
        xgconfig.write("<ServiceDetails>\n")
              
        if srv.tcprange != '':           
            listTcpPort = srv.tcprange.split(",")
            for ports in listTcpPort:
                xgconfig.write("<ServiceDetail>\n")
                xgconfig.write("<Protocol>TCP</Protocol>\n")
                
                if '-' in ports:
                    rangeport = ports.split(":")
                    xgconfig.write("<SourcePort>1:65535</SourcePort>\n")
                    xgconfig.write("<DestinationPort>"+rangeport[0].replace("-",":")+"</DestinationPort>\n")
                                                        
                else:
                    xgconfig.write("<SourcePort>1:65535</SourcePort>\n")
                    xgconfig.write("<DestinationPort>"+ports+"</DestinationPort>\n")
                
                xgconfig.write("</ServiceDetail>\n")
                               
        if srv.udprange != '':
            listUdpPort = srv.udprange.split(",")
            for ports in listUdpPort:
                xgconfig.write("<ServiceDetail>\n")
                xgconfig.write("<Protocol>UDP</Protocol>\n")
                
                if '-' in ports:
                    rangeport = ports.split(":")
                    xgconfig.write("<SourcePort>1:65535</SourcePort>\n")
                    xgconfig.write("<DestinationPort>"+rangeport[0].replace("-",":")+"</DestinationPort>\n")
                                    
                else:
                    xgconfig.write("<SourcePort>1:65535</SourcePort>\n")
                    xgconfig.write("<DestinationPort>"+ports+"</DestinationPort>\n")
                
                xgconfig.write("</ServiceDetail>\n")
        xgconfig.write("</ServiceDetails>\n")
        xgconfig.write("</Services>\n")
    
    #fcompare.write("</Services>\n")
    
def printServiceGroup(listServicesGroupObjects):
    #fcompare.write("<ServiceGroup>\n")
    
    for srvgrp in listServicesGroupObjects:
        svrgrpname = trataString(srvgrp.name)
        
        #fcompare.write("<Name>"+svrgrpname+"</Name>\n")
        
        xgconfig.write("<ServiceGroup>\n")
        xgconfig.write("<Name>"+svrgrpname+"</Name>\n")
        xgconfig.write("<Description>"+trataString(srvgrp.description)+"</Description>\n")
        xgconfig.write("<ServiceList>\n")
        
        listsrvmember = srvgrp.members.split(",")
        
        for member in listsrvmember:
            
            #fcompare.write("<Service>"+member+"</Service>\n")
            
            xgconfig.write("<Service>"+member+"</Service>\n")            
        
        xgconfig.write("</ServiceList>\n")
        xgconfig.write("</ServiceGroup>\n")
    
    #fcompare.write("<ServiceGroup>\n")    
    
def printIPSECTunnel(listIPSECTunnel):
    #print('<VPNIPSecConnection transactionid="">')
    
    for IPSEC in listIPSECTunnel:
          
        print("<Configuration>")
        print("<Name>"+IPSEC.name+"</Name>")
        print("<Description/>")
        print("<ConnectionType>TunnelInterface</ConnectionType>")
        print("<Policy>IKEv2</Policy>")
        print("<ActionOnVPNRestart>Initiate</ActionOnVPNRestart>")
        print("<AuthenticationType>PresharedKey</AuthenticationType>")
        print("<SubnetFamily>Dual</SubnetFamily>")
        print("<EndpointFamily>IPv4</EndpointFamily>")
        print("<AliasLocalWANPort>PortB</AliasLocalWANPort>")
        print("<RemoteHost>"+IPSEC.remotegateway+"</RemoteHost>")
        print("<NATedLAN/>")
        print("<LocalIDType/>")
        print("<LocalID/>")
        print("<RemoteIDType/>")
        print("<RemoteID/>")
        print("<UserAuthenticationMode>Disable</UserAuthenticationMode>")
        print("<AllowedUser>")
        print("<User/>")
        print("</AllowedUser>")
        print("<Protocol>ALL</Protocol>")
        print("<LocalPort/>")
        print("<RemotePort/>")
        print("<LocalWANPort>"+IPSEC.interface+"</LocalWANPort>")
        print("<DisconnectOnIdleInterval/>")
        print("<Status>Active</Status>")
        print('<PresharedKey passwordform="encrypt">4E9FA363BCFD2F7BA84596F21124BF86</PresharedKey>')
        print("<Username/>")
        print("<Password/>")
        print("</Configuration>")
        
def printRoute(listRouteObjects):
    """TODO Implementar comparação de rota duplicada"""
    
    #fcompare.write("<UnicastRoute>\n")
    #fcompare.write("<------- Verifcar as distância nas rotas pois não pode existir rotas com a mesma distancia no XG")
    
    for statroute in listRouteObjects:
                                        
        if statroute.routetype == 'static':
            '''
            if statroute.netdst == "":
                xgconfig.write("<GatewayHost>\n")
                xgconfig.write("<Name>"+printRoute((statroute.device)+"</Name>\n")
                xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
                xgconfig.write("<GatewayIP>"+statroute.gateway+"</GatewayIP>\n")
                xgconfig.write("<Interface>"+printRoute((statroute.device)+"</Interface>\n")
                xgconfig.write("<HealthCheck>0</HealthCheck>\n")
                xgconfig.write("<MailNotification>ON</MailNotification>\n")
                xgconfig.write("</GatewayHost>\n")
                  
            else:'''
            #fcompare.write("<DestinationIP>"+statroute.netdst+"</DestinationIP>\n")
            
            xgconfig.write("<UnicastRoute>\n")
            xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
            xgconfig.write("<DestinationIP>"+statroute.netdst+"</DestinationIP>\n")
            xgconfig.write("<Netmask>"+statroute.netmask+"</Netmask>\n")
            xgconfig.write("<Gateway>"+statroute.gateway+"</Gateway>\n")            
            
            xgvlanid = getVlanIDXGbyInterface(statroute.device)
            if xgvlanid != 'not found':
                xgvlanlang = getVlanLagInterfaceXG(statroute.device)
                xgconfig.write("<Interface>"+xgvlanlang+"."+xgvlanid+"</Interface>\n")
                
                #fcompare.write("<Interface>"+xgvlanlang+"."+xgvlanid+"</Interface>\n")
                
            else:
                xgintname = getInterfaceXG(statroute.device)
                xgconfig.write("<Interface>"+xgintname+"</Interface>\n")
                
                #fcompare.write("<Interface>"+xgintname+"</Interface>\n")
            
            # rotas duplicadas assumen routeid na distancia
            #networkandmask = (statroute.netdst+"/"+statroute.netmask)
            #print(networkandmask, statroute.device, statroute.distance, statroute.priority)
            #distance = str(findRouteDuplicated(networkandmask, statroute.device, statroute.distance, statroute.priority))
            distance = '77'
            xgconfig.write("<Distance>"+distance+"</Distance>\n")
            xgconfig.write("</UnicastRoute>\n")
            
    #fcompare.write("</UnicastRoute>\n")


def printIpsProfile(listPolicyObjects):
    listIpsprofiledup = []
    listIpsprofile = []
    
    for rule in listPolicyObjects:
        if rule.ipssensor != '':
            listIpsprofiledup.append(rule.ipssensor)
    
    listIpsprofile = list(set(listIpsprofiledup))

    
    for ipsprofile in listIpsprofile:
        xgconfig.write("<IPSPolicy>\n")
        xgconfig.write("<Name>"+ipsprofile+"</Name>\n")
        xgconfig.write("<Description>A General Policy</Description>\n")
        xgconfig.write("<RuleList>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<RuleName>Migrate_def_filter_1</RuleName>\n")
        xgconfig.write("<SignaturSelectionType>All Application</SignaturSelectionType>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>All Categories</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<SeverityList>\n")
        xgconfig.write("<Severity>All Severity</Severity>\n")
        xgconfig.write("</SeverityList>\n")
        xgconfig.write("<TargetList>\n")
        xgconfig.write("<Target>All Target</Target>\n")
        xgconfig.write("</TargetList>\n")
        xgconfig.write("<PlatformList>\n")
        xgconfig.write("<Platform>All Platform</Platform>\n")
        xgconfig.write("</PlatformList>\n")
        xgconfig.write("<SmartFilter/>\n")
        xgconfig.write("<RuleType>Default Signature</RuleType>\n")
        xgconfig.write("<Action>Recommended</Action>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("</RuleList>\n")
        xgconfig.write("</IPSPolicy>\n")

def printWebFilterProfile(listPolicyObjects):
    listWebprofiledup = []
    listWebprofile = []
    
    for rule in listPolicyObjects:
        if rule.webfilterprofile != '':
            listWebprofiledup.append(rule.webfilterprofile)
    
    listWebprofile = list(set(listWebprofiledup))
    #print(listWebprofile)
    
    for webprofile in listWebprofile:
        xgconfig.write("<WebFilterPolicy>\n")
        xgconfig.write("<Name>"+webprofile+"</Name>\n")
        xgconfig.write("<DefaultAction>Allow</DefaultAction>\n")
        xgconfig.write("<EnableReporting>Enable</EnableReporting>\n")
        xgconfig.write("<DownloadFileSizeRestriction>0</DownloadFileSizeRestriction>\n")
        xgconfig.write("<DownloadFileSizeRestrictionEnabled>0</DownloadFileSizeRestrictionEnabled>\n")
        xgconfig.write("<GoogAppDomainList/>\n")
        xgconfig.write("<GoogAppDomainListEnabled>0</GoogAppDomainListEnabled>\n")
        xgconfig.write("<YoutubeFilterIsStrict>0</YoutubeFilterIsStrict>\n")
        xgconfig.write("<YoutubeFilterEnabled>0</YoutubeFilterEnabled>\n")
        xgconfig.write("<EnforceSafeSearch>0</EnforceSafeSearch>\n")
        xgconfig.write("<EnforceImageLicensing>0</EnforceImageLicensing>\n")
        xgconfig.write("<QuotaLimit>60</QuotaLimit>\n")
        xgconfig.write("<Description>Deny access to categories most commonly unwanted in professional environments</Description>\n")
        xgconfig.write("<RuleList>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Weapons</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Extreme</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Phishing &amp; Fraud</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Militancy &amp; Extremist</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Gambling</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Criminal Activity</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Pro-Suicide &amp; Self-Harm</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Intellectual Piracy</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Marijuana</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Controlled substances</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Legal highs</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Hunting &amp; Fishing</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Anonymizers</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Sexually Explicit</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<CategoryList>\n")
        xgconfig.write("<Category>\n")
        xgconfig.write("<ID>Nudity</ID>\n")
        xgconfig.write("<type>WebCategory</type>\n")
        xgconfig.write("</Category>\n")
        xgconfig.write("</CategoryList>\n")
        xgconfig.write("<HTTPAction>Deny</HTTPAction>\n")
        xgconfig.write("<HTTPSAction>Deny</HTTPSAction>\n")
        xgconfig.write("<FollowHTTPAction>1</FollowHTTPAction>\n")
        xgconfig.write("<ExceptionList>\n")
        xgconfig.write("<FileTypeCategory/>\n")
        xgconfig.write("</ExceptionList>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("<PolicyRuleEnabled>1</PolicyRuleEnabled>\n")
        xgconfig.write("<CCLRuleEnabled>0</CCLRuleEnabled>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("</RuleList>\n")
        xgconfig.write("</WebFilterPolicy>\n")

        
def printApplicationProfile(listPolicyObjects):
    listAppprofiledup = []
    listAppprofile = []
    
    for rule in listPolicyObjects:
        if rule.applicationlist != '':
            listAppprofiledup.append(rule.applicationlist)
    
    listAppprofile = list(set(listAppprofiledup))
    #print(listAppprofile)
    
    for appprofile in listAppprofile:
        xgconfig.write("<ApplicationFilterPolicy>\n")
        xgconfig.write("<Name>"+appprofile+"</Name>\n")
        xgconfig.write("<Description>Drops traffic that are classified under very high risk apps (Risk Level- 5).</Description>\n")
        xgconfig.write("<DefaultAction>Allow</DefaultAction>\n")
        xgconfig.write("<MicroAppSupport>True</MicroAppSupport>\n")
        xgconfig.write("<RuleList>\n")
        xgconfig.write("<Rule>\n")
        xgconfig.write("<SelectAllRule>Enable</SelectAllRule>\n")
        xgconfig.write("<RiskList>\n")
        xgconfig.write("<Risk>Very High</Risk>\n")
        xgconfig.write("</RiskList>\n")
        xgconfig.write("<SmartFilter/>\n")
        xgconfig.write("<ApplicationList>\n")
        xgconfig.write("<Application>SecureLine VPN</Application>\n")
        xgconfig.write("<Application>Proxyone</Application>\n")
        xgconfig.write("<Application>Just Proxy VPN</Application>\n")
        xgconfig.write("<Application>Psiphon Proxy</Application>\n")
        xgconfig.write("<Application>ProxyProxy</Application>\n")
        xgconfig.write("<Application>SkyVPN</Application>\n")
        xgconfig.write("<Application>Amaze VPN</Application>\n")
        xgconfig.write("<Application>Stealthnet P2P</Application>\n")
        xgconfig.write("<Application>PrivateSurf.us</Application>\n")
        xgconfig.write("<Application>NapMX Retrieve P2P</Application>\n")
        xgconfig.write("<Application>Proxy Switcher Proxy</Application>\n")
        xgconfig.write("<Application>Yoga VPN</Application>\n")
        xgconfig.write("<Application>England Proxy</Application>\n")
        xgconfig.write("<Application>Gom VPN</Application>\n")
        xgconfig.write("<Application>VPN Master</Application>\n")
        xgconfig.write("<Application>Just Open VPN</Application>\n")
        xgconfig.write("<Application>Hide.Me</Application>\n")
        xgconfig.write("<Application>Bypasstunnel.com</Application>\n")
        xgconfig.write("<Application>Tiger VPN</Application>\n")
        xgconfig.write("<Application>Proxifier Proxy</Application>\n")
        xgconfig.write("<Application>FastSecureVPN</Application>\n")
        xgconfig.write("<Application>MP3 Rocket Download</Application>\n")
        xgconfig.write("<Application>TransferBigFiles Application</Application>\n")
        xgconfig.write("<Application>Cyberoam Bypass Chrome Extension</Application>\n")
        xgconfig.write("<Application>SkyEye VPN</Application>\n")
        xgconfig.write("<Application>ItsHidden Proxy</Application>\n")
        xgconfig.write("<Application>Betternet VPN</Application>\n")
        xgconfig.write("<Application>CantFindMeProxy</Application>\n")
        xgconfig.write("<Application>Shareaza P2P</Application>\n")
        xgconfig.write("<Application>DC++ Hub List P2P</Application>\n")
        xgconfig.write("<Application>Power VPN</Application>\n")
        xgconfig.write("<Application>SoftEther VPN</Application>\n")
        xgconfig.write("<Application>Surf-for-free.com</Application>\n")
        xgconfig.write("<Application>VPN Robot</Application>\n")
        xgconfig.write("<Application>Super VPN Master</Application>\n")
        xgconfig.write("<Application>UltraVPN</Application>\n")
        xgconfig.write("<Application>X-VPN</Application>\n")
        xgconfig.write("<Application>Browsec VPN</Application>\n")
        xgconfig.write("<Application>TorrentHunter Proxy</Application>\n")
        xgconfig.write("<Application>MoonVPN</Application>\n")
        xgconfig.write("<Application>Hot VPN</Application>\n")
        xgconfig.write("<Application>Super VPN</Application>\n")
        xgconfig.write("<Application>Hoxx Vpn</Application>\n")
        xgconfig.write("<Application>OpenInternet</Application>\n")
        xgconfig.write("<Application>PHProxy</Application>\n")
        xgconfig.write("<Application>VPN Monster</Application>\n")
        xgconfig.write("<Application>Cloud VPN</Application>\n")
        xgconfig.write("<Application>Speedify</Application>\n")
        xgconfig.write("<Application>RusVPN</Application>\n")
        xgconfig.write("<Application>Mute P2P</Application>\n")
        xgconfig.write("<Application>TransferBigFiles Web Download</Application>\n")
        xgconfig.write("<Application>The Pirate Bay Proxy</Application>\n")
        xgconfig.write("<Application>VPN 360</Application>\n")
        xgconfig.write("<Application>NateMail WebMail</Application>\n")
        xgconfig.write("<Application>Securitykiss Proxy</Application>\n")
        xgconfig.write("<Application>Websurf</Application>\n")
        xgconfig.write("<Application>FreeMyBrowser</Application>\n")
        xgconfig.write("<Application>uProxy</Application>\n")
        xgconfig.write("<Application>Your-Freedom Proxy</Application>\n")
        xgconfig.write("<Application>Chrome Reduce Data Usage</Application>\n")
        xgconfig.write("<Application>Unclogger VPN</Application>\n")
        xgconfig.write("<Application>Britishproxy.uk Proxy</Application>\n")
        xgconfig.write("<Application>ZenVPN</Application>\n")
        xgconfig.write("<Application>Freegate Proxy</Application>\n")
        xgconfig.write("<Application>VPN over 443</Application>\n")
        xgconfig.write("<Application>Zero VPN</Application>\n")
        xgconfig.write("<Application>Ants IRC Connect P2P</Application>\n")
        xgconfig.write("<Application>WinMX P2P</Application>\n")
        xgconfig.write("<Application>Classroom Spy</Application>\n")
        xgconfig.write("<Application>Expatshield Proxy</Application>\n")
        xgconfig.write("<Application>The Proxy Bay</Application>\n")
        xgconfig.write("<Application>OpenDoor</Application>\n")
        xgconfig.write("<Application>Snap VPN</Application>\n")
        xgconfig.write("<Application>Ultrasurf Proxy</Application>\n")
        xgconfig.write("<Application>CyberGhost VPN Proxy</Application>\n")
        xgconfig.write("<Application>Simurgh Proxy</Application>\n")
        xgconfig.write("<Application>Webproxy</Application>\n")
        xgconfig.write("<Application>Unseen Online VPN</Application>\n")
        xgconfig.write("<Application>Zalmos SSL Web Proxy for Free</Application>\n")
        xgconfig.write("<Application>VyprVPN</Application>\n")
        xgconfig.write("<Application>AppVPN</Application>\n")
        xgconfig.write("<Application>BypassGeo</Application>\n")
        xgconfig.write("<Application>Bearshare P2P</Application>\n")
        xgconfig.write("<Application>Asproxy Web Proxy</Application>\n")
        xgconfig.write("<Application>Pando P2P</Application>\n")
        xgconfig.write("<Application>Easy Proxy</Application>\n")
        xgconfig.write("<Application>VPN 365</Application>\n")
        xgconfig.write("<Application>Lantern</Application>\n")
        xgconfig.write("<Application>Office VPN</Application>\n")
        xgconfig.write("<Application>Proton VPN</Application>\n")
        xgconfig.write("<Application>Miro P2P</Application>\n")
        xgconfig.write("<Application>Morphium.info</Application>\n")
        xgconfig.write("<Application>Ants Initialization P2P</Application>\n")
        xgconfig.write("<Application>Soulseek Download P2P</Application>\n")
        xgconfig.write("<Application>FSecure Freedome VPN</Application>\n")
        xgconfig.write("<Application>QQ VPN</Application>\n")
        xgconfig.write("<Application>Tweakware VPN</Application>\n")
        xgconfig.write("<Application>Redirection Web-Proxy</Application>\n")
        xgconfig.write("<Application>Phex P2P</Application>\n")
        xgconfig.write("<Application>Hamachi VPN Streaming</Application>\n")
        xgconfig.write("<Application>Ares Retrieve Chat Room</Application>\n")
        xgconfig.write("<Application>TOR Proxy</Application>\n")
        xgconfig.write("<Application>UK-Proxy.org.uk Proxy</Application>\n")
        xgconfig.write("<Application>Winny P2P</Application>\n")
        xgconfig.write("<Application>MeHide.asia</Application>\n")
        xgconfig.write("<Application>Alkasir Proxy</Application>\n")
        xgconfig.write("<Application>Windscribe</Application>\n")
        xgconfig.write("<Application>Eagle VPN</Application>\n")
        xgconfig.write("<Application>eMule P2P</Application>\n")
        xgconfig.write("<Application>FastVPN</Application>\n")
        xgconfig.write("<Application>Boinc Messenger</Application>\n")
        xgconfig.write("<Application>Tableau Public</Application>\n")
        xgconfig.write("<Application>DotVPN</Application>\n")
        xgconfig.write("<Application>Photon Flash Player &amp; Browser</Application>\n")
        xgconfig.write("<Application>Proxysite.com Proxy</Application>\n")
        xgconfig.write("<Application>Ares Chat Room</Application>\n")
        xgconfig.write("<Application>Private Tunnel</Application>\n")
        xgconfig.write("<Application>Ares P2P</Application>\n")
        xgconfig.write("<Application>Private VPN</Application>\n")
        xgconfig.write("<Application>Epic Browser</Application>\n")
        xgconfig.write("<Application>Green VPN</Application>\n")
        xgconfig.write("<Application>GoldenKey VPN</Application>\n")
        xgconfig.write("<Application>Cyazyproxy</Application>\n")
        xgconfig.write("<Application>Hexa Tech VPN</Application>\n")
        xgconfig.write("<Application>FinchVPN</Application>\n")
        xgconfig.write("<Application>Vuze P2P</Application>\n")
        xgconfig.write("<Application>WiFree Proxy</Application>\n")
        xgconfig.write("<Application>Ninjaproxy.ninja</Application>\n")
        xgconfig.write("<Application>VPN Free</Application>\n")
        xgconfig.write("<Application>Hideman VPN</Application>\n")
        xgconfig.write("<Application>VPN Lighter</Application>\n")
        xgconfig.write("<Application>L2TP VPN</Application>\n")
        xgconfig.write("<Application>ShellFire VPN</Application>\n")
        xgconfig.write("<Application>ExpressVPN</Application>\n")
        xgconfig.write("<Application>Speedy VPN</Application>\n")
        xgconfig.write("<Application>Toonel</Application>\n")
        xgconfig.write("<Application>Torrent Clients P2P</Application>\n")
        xgconfig.write("<Application>EuropeProxy</Application>\n")
        xgconfig.write("<Application>Hi VPN</Application>\n")
        xgconfig.write("<Application>Freenet P2P</Application>\n")
        xgconfig.write("<Application>Reduh Proxy</Application>\n")
        xgconfig.write("<Application>Kugoo Playlist P2P</Application>\n")
        xgconfig.write("<Application>Frozenway Proxy</Application>\n")
        xgconfig.write("<Application>Soulseek Retrieving P2P</Application>\n")
        xgconfig.write("<Application>Hide-N-Seek Proxy</Application>\n")
        xgconfig.write("<Application>DashVPN</Application>\n")
        xgconfig.write("<Application>Phantom VPN</Application>\n")
        xgconfig.write("<Application>DNSCrypt</Application>\n")
        xgconfig.write("<Application>CrossVPN</Application>\n")
        xgconfig.write("<Application>USA IP</Application>\n")
        xgconfig.write("<Application>Total VPN</Application>\n")
        xgconfig.write("<Application>ZPN VPN</Application>\n")
        xgconfig.write("<Application>ISAKMP VPN</Application>\n")
        xgconfig.write("<Application>Hammer VPN</Application>\n")
        xgconfig.write("<Application>Speed VPN</Application>\n")
        xgconfig.write("<Application>Hotspotshield Proxy</Application>\n")
        xgconfig.write("<Application>Blockless VPN</Application>\n")
        xgconfig.write("<Application>Star VPN</Application>\n")
        xgconfig.write("<Application>RemoboVPN Proxy</Application>\n")
        xgconfig.write("<Application>SSL Proxy Browser</Application>\n")
        xgconfig.write("<Application>TurboVPN</Application>\n")
        xgconfig.write("<Application>PP VPN</Application>\n")
        xgconfig.write("<Application>VPN Unlimited</Application>\n")
        xgconfig.write("<Application>Hello VPN</Application>\n")
        xgconfig.write("<Application>SetupVPN</Application>\n")
        xgconfig.write("<Application>Astrill VPN</Application>\n")
        xgconfig.write("<Application>JAP Proxy</Application>\n")
        xgconfig.write("<Application>Heatseek Browser</Application>\n")
        xgconfig.write("<Application>ProxyWebsite</Application>\n")
        xgconfig.write("<Application>Private Internet Access VPN</Application>\n")
        xgconfig.write("<Application>DC++ Download P2P</Application>\n")
        xgconfig.write("<Application>Thunder VPN</Application>\n")
        xgconfig.write("<Application>skyZIP</Application>\n")
        xgconfig.write("<Application>TOR VPN</Application>\n")
        xgconfig.write("<Application>Haitun VPN</Application>\n")
        xgconfig.write("<Application>Bitcoin Proxy</Application>\n")
        xgconfig.write("<Application>Worldcup Proxy</Application>\n")
        xgconfig.write("<Application>Privatix VPN</Application>\n")
        xgconfig.write("<Application>Ants P2P</Application>\n")
        xgconfig.write("<Application>DC++ Connect P2P</Application>\n")
        xgconfig.write("</ApplicationList>\n")
        xgconfig.write("<Action>Deny</Action>\n")
        xgconfig.write("<Schedule>All The Time</Schedule>\n")
        xgconfig.write("</Rule>\n")
        xgconfig.write("</RuleList>\n")
        xgconfig.write("</ApplicationFilterPolicy>\n")        
        
def printAvProfile(listPolicyObjects):
    listAvprofiledup = []
    listAvprofile = []
    
    for rule in listPolicyObjects:
        if rule.avprofile != '':
            listAvprofiledup.append(rule.avprofile)
    
    listAvprofile = list(set(listAvprofiledup))
    #print(listAvprofile)
    
    for avprofile in listAvprofile:
        xgconfig.write(avprofile)
        
def printSslProfile(listPolicyObjects):
    listSslprofiledup = []
    listSslprofile = []
    
    for rule in listPolicyObjects:
        if rule.sslsshprofile != '':
            listSslprofiledup.append(rule.sslsshprofile)
    
    listSslprofile = list(set(listSslprofiledup))
    #print(listSslprofile)
    
def printPolicy(listPolicyObjects):
    srczone = []
    dstzone = []
    
    for rule in listPolicyObjects:
        
        xgconfig.write("<FirewallRule>\n")
        xgconfig.write("<Name>"+ rule.uuid +"</Name>\n")
        xgconfig.write("<Description>"+ trataString(rule.description) +"</Description>\n")
        xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
        xgconfig.write("<Status>"+ rule.status.title() +"</Status>\n")
        xgconfig.write("<Position>Bottom</Position>\n")            
        xgconfig.write("<PolicyType>Network</PolicyType>\n")
        xgconfig.write("<NetworkPolicy>\n")
        xgconfig.write("<Action>"+ rule.action.title() +"</Action>\n")
        xgconfig.write("<LogTraffic>Enable</LogTraffic>\n")
        xgconfig.write("<SkipLocalDestined>Disable</SkipLocalDestined>\n")
        
        #<!-- Source Zones -->
        xgconfig.write("<SourceZones>\n")
        listSrcintfFgt = rule.srcintf.split(",")
        
        for srcInterface in listSrcintfFgt:
            srcInt = trataInterfaceZone(srcInterface)
            if isZone(srcInt):
                 xgconfig.write("<Zone>"+srcInt+"</Zone>\n")
                 srczone.append(srcInt)
            else:
                for interfaceMap in listInterfaceZoneMap:
                    if interfaceMap.fgtint == srcInterface:
                        xgconfig.write("<Zone>"+interfaceMap.xgzone+"</Zone>\n")
                        srczone.append(interfaceMap.xgzone)
        xgconfig.write("</SourceZones>\n")
       
        #<!-- Destination Zones -->
        xgconfig.write("<DestinationZones>\n")
        listDstintfFgt = rule.dstintf.split(",")
        
        for dstInterface in listDstintfFgt:
            dstInt = trataInterfaceZone(dstInterface)
            if isZone(dstInt):
                 xgconfig.write("<Zone>"+dstInt+"</Zone>\n")
                 dstzone.append(dstInt)
            else:
                for interfaceMap in listInterfaceZoneMap:
                    if interfaceMap.fgtint == dstInterface:
                        xgconfig.write("<Zone>"+interfaceMap.xgzone+"</Zone>\n")
                        dstzone.append(interfaceMap.xgzone)
        xgconfig.write("</DestinationZones>\n")

        xgconfig.write("<Schedule>All The Time</Schedule>\n")

        #<!-- Source Networks -->            
        listSrcAddress = rule.srcaddr.split(",")
        
        if listSrcAddress[0] == 'all':
            #!@#findListRoutesbyInterfaces(rule.srcintf)
            log = 'all'
        
        else:
            xgconfig.write("<SourceNetworks>\n")                
            for srcaddress in listSrcAddress:                    
                xgconfig.write("<Network>"+trataString(srcaddress)+"</Network>\n")                    
            xgconfig.write("</SourceNetworks>\n")

        #<!-- Services -->
                 
        listService = rule.service.split(",")
        
        if listService[0] == 'ALL':
            log = 'objeto all'
            
        else:
            xgconfig.write("<Services>\n")
            for service in listService:                 
                xgconfig.write("<Service>"+trataService(service)+"</Service>\n")
            xgconfig.write("</Services>\n")
        
        ## <------ Destination -------->
        listDstAddress = rule.dstaddr.split(",")
        
        if listDstAddress[0] == 'all':
            log = 'all'
            #!@#findListRoutesbyInterfaces(rule.dstintf)            
        
        else:                
            xgconfig.write("<DestinationNetworks>\n")            
            for dstaddress in listDstAddress:                
                xgconfig.write("<Network>"+trataString(dstaddress)+"</Network>\n")                
            xgconfig.write("</DestinationNetworks>\n")
        
        xgconfig.write("<DSCPMarking>-1</DSCPMarking>\n")
        
        if rule.webfilterprofile == '':
            xgconfig.write("<WebFilter>None</WebFilter>\n")
        
        else:
            xgconfig.write("<WebFilter>"+rule.webfilterprofile+"</WebFilter>\n")
        
        xgconfig.write("<WebCategoryBaseQoSPolicy> </WebCategoryBaseQoSPolicy>\n")
        xgconfig.write("<BlockQuickQuic>Disable</BlockQuickQuic>\n")
        xgconfig.write("<ScanVirus>Disable</ScanVirus>\n")
        xgconfig.write("<Sandstorm>Disable</Sandstorm>\n")
        xgconfig.write("<ProxyMode>Disable</ProxyMode>\n")
        xgconfig.write("<DecryptHTTPS>Disable</DecryptHTTPS>\n")
        
        if rule.applicationlist == '':
            xgconfig.write("<ApplicationControl>None</ApplicationControl>\n")
        
        else:
            xgconfig.write("<ApplicationControl>"+rule.applicationlist+"</ApplicationControl>\n")
            
        
        xgconfig.write("<ApplicationBaseQoSPolicy> </ApplicationBaseQoSPolicy>\n")
        
        if rule.ipssensor == '':
            xgconfig.write("<IntrusionPrevention>None</IntrusionPrevention>\n")
        
        else:
            xgconfig.write("<IntrusionPrevention>"+rule.ipssensor+"</IntrusionPrevention>\n")            
        
        xgconfig.write("<TrafficShappingPolicy>None</TrafficShappingPolicy>\n")
        xgconfig.write("<ScanSMTP>Disable</ScanSMTP>\n")
        xgconfig.write("<ScanSMTPS>Disable</ScanSMTPS>\n")
        xgconfig.write("<ScanIMAP>Disable</ScanIMAP>\n")
        xgconfig.write("<ScanIMAPS>Disable</ScanIMAPS>\n")
        xgconfig.write("<ScanPOP3>Disable</ScanPOP3>\n")
        xgconfig.write("<ScanPOP3S>Disable</ScanPOP3S>\n")
        xgconfig.write("<ScanFTP>Disable</ScanFTP>\n")
        xgconfig.write("<SourceSecurityHeartbeat>Disable</SourceSecurityHeartbeat>\n")
        xgconfig.write("<MinimumSourceHBPermitted>No Restriction</MinimumSourceHBPermitted>\n")
        xgconfig.write("<DestSecurityHeartbeat>Disable</DestSecurityHeartbeat>\n")
        xgconfig.write("<MinimumDestinationHBPermitted>No Restriction</MinimumDestinationHBPermitted>\n")
        xgconfig.write("</NetworkPolicy>\n")
        xgconfig.write("</FirewallRule>\n")
            
        if rule.sslsshprofile != '':
            
            xgconfig.write("<SSLTLSInspectionRule>\n")
            xgconfig.write("<Name>"+ rule.uuid +"</Name>\n")
            xgconfig.write("<IsDefault>No</IsDefault>\n")
            xgconfig.write("<Description>"+ rule.uuid +"</Description>\n")
            xgconfig.write("<Enable>Yes</Enable>\n")
            xgconfig.write("<LogConnections>Enable</LogConnections>\n")
            
            #<!-- Source Zones -->
            xgconfig.write("<SourceZones>\n")
            listSrcintfFgt = rule.srcintf.split(",")
            
            for srcInterface in listSrcintfFgt:
                srcInt = trataInterfaceZone(srcInterface)
                if isZone(srcInt):
                     xgconfig.write("<Zone>"+srcInt+"</Zone>\n")
                else:
                    for interfaceMap in listInterfaceZoneMap:
                        if interfaceMap.fgtint == srcInterface:
                            xgconfig.write("<Zone>"+interfaceMap.xgzone+"</Zone>\n")
            xgconfig.write("</SourceZones>\n")            
            
            #<!-- Source Networks -->            
            listSrcAddress = rule.srcaddr.split(",")
            
            if listSrcAddress[0] == 'all':
                log = "objeto all"
                xgconfig.write("<SourceNetworks>\n")
                xgconfig.write("<Network>Any</Network>\n")
                xgconfig.write("</SourceNetworks>\n")
            
            else:
                xgconfig.write("<SourceNetworks>\n")                
                for srcaddress in listSrcAddress:                    
                    xgconfig.write("<Network>"+trataString(srcaddress)+"</Network>\n")                    
                xgconfig.write("</SourceNetworks>\n")
            
            xgconfig.write("<Identity>\n")
            xgconfig.write("<Members>Anybody</Members>\n")
            xgconfig.write("</Identity>\n")
            
            #<!-- Destination Zones -->
            xgconfig.write("<DestinationZones>\n")
            listDstintfFgt = rule.dstintf.split(",")
            
            for dstInterface in listDstintfFgt:
                dstInt = trataInterfaceZone(dstInterface)
                if isZone(dstInt):
                     xgconfig.write("<Zone>"+dstInt+"</Zone>\n")
                else:
                    for interfaceMap in listInterfaceZoneMap:
                        if interfaceMap.fgtint == dstInterface:
                            xgconfig.write("<Zone>"+interfaceMap.xgzone+"</Zone>\n")
            xgconfig.write("</DestinationZones>\n")
            
            ## <------ Destination -------->
            listDstAddress = rule.dstaddr.split(",")
            
            if listDstAddress[0] == 'all':
                #xgconfig.write("objeto all + log\n")
                log = "objeto all"
                xgconfig.write("<DestinationNetworks>\n")
                xgconfig.write("<Network>Any</Network>\n")
                xgconfig.write("</DestinationNetworks>\n")
                
            else:                
                xgconfig.write("<DestinationNetworks>\n")            
                for dstaddress in listDstAddress:                
                    xgconfig.write("<Network>"+trataString(dstaddress)+"</Network>\n")                
                xgconfig.write("</DestinationNetworks>\n")
            
            #<!-- Services -->
                     
            listService = rule.service.split(",")
            
            if listService[0] == 'ALL':
                log = 'objeto all'
                
            else:
                xgconfig.write("<Services>\n")
                for service in listService:                 
                    xgconfig.write("<Service>"+trataService(service)+"</Service>\n")
                xgconfig.write("</Services>\n")
            
            xgconfig.write("<Websites>\n")
            xgconfig.write("<Activity>\n")
            xgconfig.write("<Name>Any</Name>\n")
            xgconfig.write("<Type/>\n")
            xgconfig.write("</Activity>\n")
            xgconfig.write("</Websites>\n")
            xgconfig.write("<DecryptAction>Decrypt</DecryptAction>\n")
            xgconfig.write("<DecryptionProfile>Maximum compatibility</DecryptionProfile>\n")
            xgconfig.write("</SSLTLSInspectionRule>\n")
            
            
        if rule.action == 'accept':
            
            if rule.policytype == 'Masquerade':
               
                xgconfig.write("<NATRule>\n")
                xgconfig.write("<Name>MASQ->"+rule.uuid+"</Name>\n")
                xgconfig.write("<Description/>\n")
                xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
                xgconfig.write("<Status>Enable</Status>\n")
                xgconfig.write("<Position>Bottom</Position>\n")
                xgconfig.write("<LinkedFirewallrule>"+rule.uuid+"</LinkedFirewallrule>\n")
                xgconfig.write("<TranslatedDestination>Original</TranslatedDestination>\n")
                xgconfig.write("<TranslatedService>Original</TranslatedService>\n")
                xgconfig.write("<OverrideInterfaceNATPolicy>Enable</OverrideInterfaceNATPolicy>\n")
                xgconfig.write("<TranslatedSource>Original</TranslatedSource>\n")
                xgconfig.write("<InterfaceNATPolicyList>\n")
                
                interf = findInteraceVlanidonSophos(rule.dstintf)
                
                if isZone(interf):
                    xgintzones = getInterfaceZone(interf)
                    for fgtint in xgintzones:
                        xgint = getInterfaceXG(fgtint)
                        xgvlanint = findInteraceVlanidonSophos(xgint)
                        xgconfig.write("<Override>\n")         
                        xgconfig.write("<specific_interface>"+xgvlanint+"</specific_interface>\n")
                        xgconfig.write("<specific_translatedsourceid>MASQ</specific_translatedsourceid>\n")
                        xgconfig.write("</Override>\n")                                      
                    
                else:                
                    xgconfig.write("<Override>\n")         
                    xgconfig.write("<specific_interface>"+interf+"</specific_interface>\n")
                    xgconfig.write("<specific_translatedsourceid>MASQ</specific_translatedsourceid>\n")
                    xgconfig.write("</Override>\n")
                
                xgconfig.write("</InterfaceNATPolicyList>\n")                  
                xgconfig.write("</NATRule>\n")
                
            if rule.policytype == 'SNAT':
                
                listIPpool = rule.ippoolnames.split(",")
           
                ruleuuisub = rule.uuid[0:16]
                    
                xgconfig.write("<NATRule>\n")
                xgconfig.write("<Name>SNAT->"+ rule.uuid +"</Name>\n")
                xgconfig.write("<Description>SNAT->"+ rule.uuid + "migration tool</Description>\n")
                xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
                xgconfig.write("<Status>Enable</Status>\n")
                xgconfig.write("<Position>Bottom</Position>\n")
                xgconfig.write("<LinkedFirewallrule>"+rule.uuid+"</LinkedFirewallrule>\n")                    
                xgconfig.write("<TranslatedDestination>Original</TranslatedDestination>\n")
                xgconfig.write("<TranslatedService>Original</TranslatedService>\n")            
                xgconfig.write("<OverrideInterfaceNATPolicy>Enable</OverrideInterfaceNATPolicy>\n")
                xgconfig.write("<TranslatedSource>Original</TranslatedSource>\n")
                xgconfig.write("<InterfaceNATPolicyList>\n")           
    
                for ippoolname in listIPpool:
                    interf = findInterfaceIppoolByName(ippoolname)
                    
                    xgconfig.write("<Override>\n")
                    xgconfig.write("<specific_interface>"+interf+"</specific_interface>\n")
                    xgconfig.write("<specific_translatedsourceid>"+ippoolname+"</specific_translatedsourceid>\n")
                    xgconfig.write("</Override>\n")
                    
                xgconfig.write("</InterfaceNATPolicyList>\n")
                xgconfig.write("</NATRule>\n")
                
               
            if rule.policytype == 'VirtualIP':
               
                listvip = rule.dstaddr.split(",")
                
                for vipname in listvip:
                    ruleuuisub = rule.uuid[0:9]
                    
                    xgconfig.write("<NATRule>\n")
                    xgconfig.write("<Name>DNAT->"+ruleuuisub+vipname+"</Name>\n")                
                    xgconfig.write("<Description>DNAT->"+rule.uuid+"->"+vipname+" migration tool</Description>\n")
                    xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
                    xgconfig.write("<Status>Enable</Status>\n")
                    xgconfig.write("<Position>Bottom</Position>\n")
                    xgconfig.write("<LinkedFirewallrule>None</LinkedFirewallrule>\n")
                    xgconfig.write("<OriginalDestinationNetworks>\n")
                    xgconfig.write("<Network>"+vipname+"_EXT</Network>\n")
                    xgconfig.write("</OriginalDestinationNetworks>\n")
                    xgconfig.write("<TranslatedDestination>"+vipname+"_INT</TranslatedDestination>\n")
                    
                    
                    #<!-- Services -->            
                    listService = rule.service.split(",")
                    if listDstAddress[0] == 'all':
                        #xgconfig.write("objeto all + log\n")
                        log = "objeto all"
                    
                    else:
                        xgconfig.write("<OriginalServices>\n")
                        for service in listService:                 
                            xgconfig.write("<Service>"+trataService(service)+"</Service>\n")
                        xgconfig.write("</OriginalServices>\n")
                    
                    
                    xgconfig.write("<TranslatedService>Original</TranslatedService>\n")
                    xgconfig.write("<OverrideInterfaceNATPolicy>Disable</OverrideInterfaceNATPolicy>\n")
                    xgconfig.write("<TranslatedSource>Original</TranslatedSource>\n")
                    xgconfig.write("<NATMethod>0</NATMethod>\n")
                    xgconfig.write("<HealthCheck>Disable</HealthCheck>\n")
                    xgconfig.write("</NATRule>\n")
                          
                    xgconfig.write("<NATRule>\n")
                    xgconfig.write("<Name>Loopback->"+ruleuuisub+vipname+"</Name>\n")
                    xgconfig.write("<Description>Loopback->"+rule.uuid+"->"+vipname+"</Description>\n")
                    xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
                    xgconfig.write("<Status>Enable</Status>\n")
                    xgconfig.write("<Position>Bottom</Position>\n")
                    xgconfig.write("<LinkedFirewallrule>None</LinkedFirewallrule>\n")
                    xgconfig.write("<OriginalDestinationNetworks>\n")
                    xgconfig.write("<Network>"+vipname+"_EXT</Network>\n")
                    xgconfig.write("</OriginalDestinationNetworks>\n")
                    xgconfig.write("<TranslatedDestination>"+vipname+"_INT</TranslatedDestination>\n")
                    
                    if listDstAddress[0] == 'all':
                        #xgconfig.write("objeto all + log\n")
                        log = "objeto all"
                    
                    else:
                        xgconfig.write("<OriginalServices>\n")
                        for service in listService:                 
                            xgconfig.write("<Service>"+trataService(service)+"</Service>\n")
                        xgconfig.write("</OriginalServices>\n")
                    
                    xgconfig.write("<TranslatedService>Original</TranslatedService>\n")
                    xgconfig.write("<OverrideInterfaceNATPolicy>Disable</OverrideInterfaceNATPolicy>\n")
                    xgconfig.write("<TranslatedSource>MASQ</TranslatedSource>\n")
                    xgconfig.write("<NATMethod>0</NATMethod>\n")
                    xgconfig.write("<HealthCheck>Disable</HealthCheck>\n")
                    xgconfig.write("</NATRule>\n")
                    xgconfig.write("<NATRule>\n")
                    
                    xgconfig.write("<Name>Reflexive_NAT->"+ruleuuisub+vipname+"</Name>\n")
                    xgconfig.write("<Description>Reflexive_NAT->"+rule.uuid+"->"+vipname+"</Description>\n")
                    xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
                    xgconfig.write("<Status>Enable</Status>\n")
                    xgconfig.write("<Position>Bottom</Position>\n")
                    xgconfig.write("<LinkedFirewallrule>None</LinkedFirewallrule>\n")
                    xgconfig.write("<OriginalSourceNetworks>\n")
                    xgconfig.write("<Network>"+vipname+"_INT</Network>\n")
                    xgconfig.write("</OriginalSourceNetworks>\n")
                    xgconfig.write("<TranslatedDestination>Original</TranslatedDestination>\n")
                    xgconfig.write("<TranslatedService>Original</TranslatedService>\n")
                    xgconfig.write("<OverrideInterfaceNATPolicy>Disable</OverrideInterfaceNATPolicy>\n")
                    xgconfig.write("<TranslatedSource>"+vipname+"_EXT</TranslatedSource>\n")
                    xgconfig.write("</NATRule>\n")
                
        #print(srczone)
        #print(dstzone)
        srczone.clear()
        dstzone.clear()        
    #fcompare.write("</FirewallRule>\n")        

def printInterfaceMAP(listInterfaceZoneMap):
    global gvdom

    for intMap in listInterfaceZoneMap:
        
        # Cria interfaces de acordo com a vdom!        
        if (intMap.fgtvdom == gvdom):

            if intMap.xginttype == 'aggregate':
                ips = extractIPs(intMap.xgintips)
                ipMask = splitIpMask(ips[0])
                
                if len(ipMask) > 1:                
                
                    listintf = extractInterface(intMap.xgintvlanlag)
                    
                    xgconfig.write("<LAG>\n")
                    xgconfig.write("<Hardware>"+intMap.xgintname+"</Hardware>\n")
                    xgconfig.write("<Name>"+intMap.xgintname+"</Name>\n")
                    
                    xgconfig.write("<MemberInterface>\n")
                    
                    for intf in listintf:
                        xgconfig.write("<Interface>"+intf+"</Interface>\n")            
                    
                    xgconfig.write("</MemberInterface>\n")
                    
                    xgconfig.write("<Mode>802.3ad(LACP)</Mode>\n")
                    xgconfig.write("<NetworkZone>"+intMap.xgzone+"</NetworkZone>\n")
                    xgconfig.write("<IPAssignment>Static</IPAssignment>\n")
                    xgconfig.write("<IPv4Configuration>Enable</IPv4Configuration>\n")
                    xgconfig.write("<IPv6Configuration>Disable</IPv6Configuration>\n")
                    xgconfig.write("<InterfaceSpeed>1000MbpsFD</InterfaceSpeed>\n")
                    xgconfig.write("<MTU>1500</MTU>\n")
                    xgconfig.write("<MACAddress>Default</MACAddress>\n")
                    xgconfig.write("<MSS>\n")
                    xgconfig.write("<OverrideMSS>Disable</OverrideMSS>\n")
                    xgconfig.write("<MSSValue>1460</MSSValue>\n")
                    xgconfig.write("</MSS>\n")
                    
                    xgconfig.write("<IPv4Address>"+ipMask[0]+"</IPv4Address>\n")
                    xgconfig.write("<Netmask>"+ipMask[1]+"</Netmask>\n")
                    
                    xgconfig.write("<XmitHashPolicy>Layer2</XmitHashPolicy>\n")
                    xgconfig.write("</LAG>\n")
    
    for intMap in listInterfaceZoneMap:
        # Cria interfaces de acordo com a vdom!        
        if (intMap.fgtvdom == gvdom):
            
            if intMap.xginttype == 'physical':
                #extrair ip/mask
                ips = extractIPs(intMap.xgintips)
                ipMask = splitIpMask(ips[0])
                            
                if len(ipMask) > 1:
                    xgconfig.write("<Interface>\n")
                    xgconfig.write("<IPv4Configuration>Enable</IPv4Configuration>\n")
                    xgconfig.write("<IPv6Configuration>Disable</IPv6Configuration>\n")
                    xgconfig.write("<Hardware>"+intMap.xgintname+"</Hardware>\n")
                    xgconfig.write("<Name>"+intMap.xgintname+"</Name>\n")
                    xgconfig.write("<NetworkZone>"+intMap.xgzone+"</NetworkZone>\n")
                    xgconfig.write("<IPv4Assignment>Static</IPv4Assignment>\n")
                    xgconfig.write("<IPv6Assignment/>\n")
                    xgconfig.write("<DHCPRapidCommit>Disable</DHCPRapidCommit>\n")
                    xgconfig.write("<InterfaceSpeed>Auto Negotiate</InterfaceSpeed>\n")
                    xgconfig.write("<MTU>1500</MTU>\n")
                    xgconfig.write("<MSS>\n")
                    xgconfig.write("<OverrideMSS>Disable</OverrideMSS>\n")
                    xgconfig.write("<MSSValue>1460</MSSValue>\n")
                    xgconfig.write("</MSS>\n")
                    xgconfig.write("<MACAddress>Default</MACAddress>\n")
                    xgconfig.write("<IPAddress>"+ipMask[0]+"</IPAddress>\n")
                    xgconfig.write("<Netmask>"+ipMask[1]+"</Netmask>\n")
                    
                    if intMap.xgzone == 'WAN':
                        xgconfig.write("<GatewayName>"+intMap.xgintname+"</GatewayName>\n")
                        xgconfig.write("<GatewayAddress>"+"ipdainterface"+"</GatewayAddress>\n")
                        xgconfig.write("<GatewayIP/>\n")
                    else:
                        xgconfig.write("<GatewayName/>\n")
                        xgconfig.write("<GatewayAddress/>\n")
                        xgconfig.write("<GatewayIP/>\n")              
                    
                    xgconfig.write("</Interface>\n")
            
            if intMap.xginttype == 'VLAN':
                hardware = trataString(intMap.xgintvlanlag) + "." + intMap.xgvlanid
                interf = trataString(intMap.xgintvlanlag)
                
                #extrair ip/mask
                ips = extractIPs(intMap.xgintips)
                ipMask = splitIpMask(ips[0])
                
                if len(ipMask) > 1:            
                    xgconfig.write("<VLAN>\n")
                    xgconfig.write("<Zone>" + intMap.xgzone + "</Zone>\n")
                    xgconfig.write("<Interface>" + interf + "</Interface>\n")
                    xgconfig.write("<Hardware>" + hardware + "</Hardware>\n")
                    xgconfig.write("<Name>" + intMap.xgintname + "</Name>\n")
                    xgconfig.write("<VLANID>" + intMap.xgvlanid + "</VLANID>\n")
                    xgconfig.write("<IPv4Configuration>Enable</IPv4Configuration>\n")
                    xgconfig.write("<IPv6Configuration>Disable</IPv6Configuration>\n")
                    xgconfig.write("<IPv4Assignment>Static</IPv4Assignment>\n")
                    xgconfig.write("<IPv6Address/>\n")
                    xgconfig.write("<IPv6Prefix/>\n")
                    xgconfig.write("<IPv6GatewayName/>\n")
                    xgconfig.write("<IPv6GatewayAddress/>\n")
                    xgconfig.write("<LocalIP/>\n")
                    xgconfig.write("<Status></Status>\n")
                    xgconfig.write("<IPv6Assignment/>\n")
                    xgconfig.write("<DHCPRapidCommit/>\n")
                    xgconfig.write("<IPAddress>" + ipMask[0] + "</IPAddress>\n")
                    xgconfig.write("<Netmask>"+ipMask[1]+"</Netmask>\n")
                    
                    if intMap.xgzone == 'WAN':
                        gatewayip = getIpGatewaybyInterface(intMap.xgintname)
                        
                        xgconfig.write("<GatewayName>"+intMap.xgintname+"</GatewayName>\n")                    
                        xgconfig.write("<GatewayAddress>"+gatewayip+"</GatewayAddress>\n")
                        xgconfig.write("<GatewayIP/>\n")
                    else:
                        xgconfig.write("<GatewayName/>\n")
                        xgconfig.write("<GatewayAddress/>\n")
                        xgconfig.write("<GatewayIP/>\n") 
                        
                    xgconfig.write("</VLAN>\n")
                        

def printZones(listZoneObjects):
    for zone in listZoneObjects:
        xgconfig.write("<Zone>\n")
        xgconfig.write("<Name>"+zone.name+"</Name>\n")
        xgconfig.write("<Type>LAN</Type>\n")
        xgconfig.write("<Description/>\n")
        xgconfig.write("<ApplianceAccess>\n")
        xgconfig.write("<AdminServices>\n")
        xgconfig.write("<HTTPS>Enable</HTTPS>\n")
        #xgconfig.write("<SSH>Enable</SSH>\n")
        xgconfig.write("</AdminServices>\n")
        xgconfig.write("<AuthenticationServices>\n")
        xgconfig.write("<ClientAuthentication>Enable</ClientAuthentication>\n")
        xgconfig.write("<CaptivePortal>Enable</CaptivePortal>\n")
        #xgconfig.write("<RadiusSSO>Enable</RadiusSSO>\n")
        xgconfig.write("</AuthenticationServices>\n")
        xgconfig.write("<NetworkServices>\n")
        #xgconfig.write("<DNS>Enable</DNS>\n")
        xgconfig.write("<Ping>Enable</Ping>\n")
        xgconfig.write("</NetworkServices>\n")
        xgconfig.write("<OtherServices>\n")
        #xgconfig.write("<WebProxy>Enable</WebProxy>\n")
        #xgconfig.write("<SSLVPN>Enable</SSLVPN>\n")
        xgconfig.write("<UserPortal>Enable</UserPortal>\n")
        xgconfig.write("<WirelessProtection>Enable</WirelessProtection>\n")
        #xgconfig.write("<SMTPRelay>Enable</SMTPRelay>\n")
        #xgconfig.write("<SNMP>Enable</SNMP>\n")
        xgconfig.write("</OtherServices>\n")
        xgconfig.write("</ApplianceAccess>\n")
        xgconfig.write("</Zone>\n")
    
def isAddress(addr):
    isAddr = False
    
    for address in listAddressObjects:
        if address.name == addr:
            isAddr = True
            break
    
    if isAddr == False:
        print ("Adress Não encontrado " + addr)
    
    return isAddr

def isVIP(addr):
    isVIP = False

    for vip in listVirtualIPObjects:
        if addr == vip.name:
            isVIP = True
            break
            
    return isVIP

def isVipGroup(addr):
    isVipGroup = False

    for grpvip in listVIPGroupObjects:
        if addr == grpvip.name:
            isVipGroup = True
            break
            
    return isVipGroup
   
def isZone(string):
    founded = False
    for zone in listZoneObjects:
        if zone.name == string:
            founded = True
            break
    return founded


def getIpGatewaybyInterface(intf):
    gatewayip = 'not found'
    for route in listRouteObjects:

        if route.routetype == 'gateway':
            #obetndo interface XG
            xgint = getInterfaceXG(route.device)
            
            if xgint == intf:
                gatewayip = route.gateway
                break
    
    return gatewayip



def getVlanIDXGbyInterface(fgtint):
    xgvlanid = 'not found'
    
    for intmap in listInterfaceZoneMap:
        if intmap.xginttype == 'VLAN':            
            if fgtint == intmap.fgtint:
                xgvlanid = intmap.xgvlanid
            
    #if xgvlanid == 'not found':
        #flog.write("[ERRO][INTERFACE]=" + fgtint + "Nao encontrado VLANID\n")
            
    return xgvlanid

def getVlanLagInterfaceXG(fgtint):
    xgvlanlag = 'not found'
    
    for intmap in listInterfaceZoneMap:
        if intmap.xginttype == 'VLAN':            
            if fgtint == intmap.fgtint:
                xgvlanlag = intmap.xgintvlanlag
                xgvlanlag = trataString(xgvlanlag)
                break
            
    """ Implementar agreggation
        for intmap in listInterfaceZoneMap:
        if intmap.xginttype == 'VLAN':            
            if fgtint == intmap.:
                xgvlanid = intmap.xgvlanid
                break
    """
            
    #if xgvlanlag == 'not found':
        #flog.write("[ERRO][INTERFACE]=" + fgtint + "Nao encontrado Interface VLANID\n")
            
    return xgvlanlag

def isRouteDefault(intf):
    for route in listRouteObjects:
        if route.device == intf:
            print(route.routetype)
            print(route.netdst)
    
def findZone(zone):
    zoneobj = InterfaceZone("null","","")
    
    for xzone in listZoneObjects:
        if xzone.name == zone:
            zoneobj = xzone
    
    return zoneobj            
    

def findListRoutesbyInterfaces(intfs):
    xginterface = ''
    
    interfaces = intfs.split(",")
    #print(intfs)
    
    for intf in interfaces:
        
        xgzone = trataInterfaceZone(intf)
        
        if isZone(xgzone):
            
            zoneobj = findZone(xgzone)
            print(zoneobj.interfaces)
            
            zinterfaces = zoneobj.interfaces.split(",")
            
            for zintf in zinterfaces:
                isRouteDefault(zintf)
            #print(xgzone)
            #print(intf)                    
            #print("zona-> " + intf)
    

         
        #else:
            #for interfaceMap in listInterfaceZoneMap:
                #print("interface xg ->" +interfaceMap.xgintname)
                #if interfaceMap.fgtint == intf:
                    #print("interface xg ->" +interfaceMap.xgintname)
    
   
def findRouteDuplicated(network,device,distance,priority):
    ##Implementar comparação de distancia e prioridade.
    distance = distance
    netandmask = ipaddress.IPv4Network(network)
    #print (device)
    
    for route in listRouteObjects:
        
        if route.routetype == 'static':
            
            routenetandmask = ipaddress.IPv4Network(route.netdst+"/"+route.netmask)
            
            if netandmask == routenetandmask:
                
                if route.device != device:
                    
                    distance = int(route.routerid)  
                                  
                    #xgconfig.write(route.netmask+","+route.netdst+"!@#$$"+device + str(distance))
                    
                    #flog.write("[ERRO][ROUTE] Rota duplicada verificar distancia" + route.netdst+"/"+ route.netmask + " interface = " + device +"\n")
                    
                    break
                
    return distance

def getInterfaceZone(zone):
    xglistinterface = ['not found']
    
    for zn in listZoneObjects:
        if zn.name == zone:
            xglistinterface = zn.interfaces.split(",")
            break
            
    #if xglistinterface[0] == 'not found':
        #flog.write("[ERRO][INTERFACE]=" + zone + "Nao encontrado Zona\n")
            
    return xglistinterface

def getInterfaceXG(fgtint):
    xgint = 'not found'
    
    for intmap in listInterfaceZoneMap:
        if fgtint == intmap.fgtint:
            xgint = intmap.xgintname
            break
            
    #if xgint == 'not found':
        #flog.write("[ERRO][INTERFACE]=" + fgtint + "Nao encontrado interface\n")
            
    return xgint   
    
    
def findAddress(addrname):
    addrobj = Address("null","","","","","","","") 
    
    for addr in listAddressObjects:
        if addr.name == addrname:
            addrobj = addr
    
    #if addrobj.name == 'null':
        #flog.write("[ERRO] Address=" + addrname + " Nao encontrado\n") 
    
    return addrobj

def findAddressGroup(addrgrpname):
    addrgrpobj = AddressGroup('null','','')
    
    for addrgrp in listAddressGroupObjects:
        if addrgrp.name == addrgrpname:
            addrgrpobj = addrgrp
    
    #if addrgrpobj.name == 'null':
        #flog.write("[ERRO] Group=" + addrgrpname + " Nao encontrado\n") 
    
    return addrgrpobj

def findInterfaceIppoolByName(ippoolname):
    #ippoolobj = IPpool('not found', '', '', '')
    intf = 'not found'
    
    for ippool in listIPpoolObjects:
        
        if ippool.name == ippoolname:
            #xgconfig.write(ippool.startip+"/32")
            intf = findInterfaceInRoutebyIP(ippool.startip+"/32")       
    
    return intf
    
    
def findInterfaceInRoutebyIP(ipwthnetmask):
    instf = 'not found'
    
    for route in listRouteObjects:
        
        if route.netdst != '':
            netdiff = ipaddress.IPv4Interface(ipwthnetmask).network
            networkroute = ipaddress.IPv4Network(route.netdst+"/"+route.netmask)
            
            overlap = netdiff.overlaps(networkroute)
            
            if overlap:
                instf = route.device
                instf = findInteraceVlanidonSophos(instf)
                break
       
    return instf

def findInteraceVlanidonSophos(instf):
    # criar para o aggregation
    xgvlanlag = instf 
    
    for intMap in listInterfaceZoneMap:
        if instf == intMap.xgintname:
            if intMap.xginttype == 'VLAN':
                xgvlanlag = trataString(intMap.xgintvlanlag) + "." + intMap.xgvlanid
                                
            if intMap.xginttype == 'aggregation':
                ##implementar
                xgconfig.write(intMap.xgintvlanlag)
                
    return xgvlanlag        
    

def findVip(vipname):
    vipobj = VirtualIP("null", "", "", "", "", "", "") 
    
    for vip in listVirtualIPObjects:
        if vip.name == vipname:
            vipobj = vip
        
    if vipobj.name == 'null':
        xgconfig.write("VIP nao encontrado-> " + vipname)    
    
    return vipobj
    
    
def findService(service):
    find = False
    
    for srv in listServicesObjects:
        if service == srv.name:
            find = True
            #xgconfig.write("encontrado -> "+service)
            break
    
    #if find == False:
        #xgconfig.write("Serviço não encontrado " + service)        
        
    return find

def findServiceGroup(grpService):
    find = False
    
    for grpsrv in listServicesGroupObjects:
        if grpService == grpsrv.name:
            find = True
            #xgconfig.write("grupo encontrado -> "+grpService)
            break
    
    #if find == False:
        #xgconfig.write("grupo de Serviço não encontrado " + grpService)        
        
    return find

def isFQDN(fqdn):
    founded = False
            
    for address in listAddressObjects:
        if address.name == fqdn:
            if address.hosttype == "FQDNHost":
                founded = True
                break
    
    return founded
                        
def my_range(start, end, step):
    while start <= end:
        yield start
        start += step

def printAlias(listInterfaceZoneMap):
    #TODO carregar todos os alias antes de imprimir
    for intMap in listInterfaceZoneMap:
        #extrai os ips
        ips = extractIPs(intMap.xgintips)
        #se possuir ips
        if ips[0] != "":
            #se possuir ips secundários
            if len(ips) > 1:
                # imprime apartir do segundo ip de interface
                for x in my_range(2,len(ips),1):
                    xgconfig.write("<Alias>\n")
                    xgconfig.write("<Interface>"+intMap.xgintname+"</Interface>\n")
                    xgconfig.write("<Name>TesteAlias</Name>\n")
                    xgconfig.write("<IPFamily>IPv4</IPFamily>\n")
                    xgconfig.write("<IPAddress>"+str(splitIpMask(ips[x-1])[0])+"</IPAddress>\n")
                    xgconfig.write("<Netmask>"+str(splitIpMask(ips[x-1])[1])+"</Netmask>\n")
                    xgconfig.write("</Alias>\n")
               
def loadInterfaceZoneMAP(interZoneMap):
    filepath = interZoneMap
    #f = open(filepath, encoding="utf8")
    f = open(filepath, encoding="ISO-8859-1")
    line = f.readline()
    
    #pula o cabeçalho
    line = f.readline()
    
    while line:
        line = line.strip()
        
        auxMAP = line.split(',')
        
        fgtint = auxMAP[0]
        fgtips = auxMAP[1]
        fgtintftype = auxMAP[2]
        fgtvlanid = auxMAP[3]
        fgtintvlanlag = auxMAP[4]
        fgtvdom = auxMAP[5]
        xgintname = auxMAP[6]
        xgintips = auxMAP[7]
        xginttype = auxMAP[8]
        xgvlanid = auxMAP[9]
        xgintvlanlag = auxMAP[10]
        xgzone = auxMAP[11]
        description = 'Migration Tool'
        
        listInterfaceZoneMap.append(InterfaceZoneMap(fgtint, fgtips, fgtintftype, fgtvlanid, fgtintvlanlag, fgtvdom, xgintname, xgintips, xginttype, xgvlanid, xgintvlanlag, xgzone, description))
        
        
        if '[]' != xgintips:
            
            #ip = ipaddress.IPv4Interface("192.168.25.26/24").network
            ips = xgintips 
            intf = xgintname
            
            nets = extractIPs(ips)
            
            firstnet = ipaddress.IPv4Interface(nets[0]).network
                        
            listRouteObjects.append(Route('7777777', str(firstnet.network_address), str(firstnet.netmask), '', intf, '', '', 'direct', 'network of interface'))
            
            for route in nets:
                net = ipaddress.IPv4Interface(route).network
                if firstnet != net:
                    listRouteObjects.append(Route('7777777', str(net.network_address), str(net.netmask), '', intf, '', '', 'direct', 'network of interface'))
         

            
            #xgconfig.write(ip)
            
        line = f.readline()
    
    f.close()

def trataService(service):
    if service == "ALL_TCP":
        service = "TCP"
    if service == "ALL_UDP":
        service = "UDP"
    if service == "ALL_ICMP":
        service = "ICMP"
    
    return service

def trataString(string):
    #trata caracter especial
    
    if "https://" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("https://","")
        
    if "http://" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("http://","")
    
    if "[" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("[","")
    
    if "]" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("]","")

    if "&" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("&","-")        
        
    if "ç" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("ç","c")
        
    if "ã" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("ã","a")
        
    if "á" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("á","a")

    if "à" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("à","a")
        
    if "é" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("é","e")
        
    if "ê" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("ê","e")

    if "í" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("í","i")        

    if "ó" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("ó","o")
        
    if "õ" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("õ","o")
    
    if "ô" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("ô","o")
        
    if "ú" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("ú","u")
        
    '''
    if "/" in string:
        xgconfig.write("contem caractere especial " + string)
        string = string.replace("/","-")
    '''    
    if "\\" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("\\","-")
    
    if "br*" in string:
        #trata * no final do fqdn
        string = string.replace("br*","br")
    
    if "com*" in string:
        #trata * no final do fqdn
        string = string.replace("com*","br")
        
         
    return string

def trataFQDN(string):
    #trata caracter especial
    
    if "https://" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("https://","")
        
    if "http://" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("http://","")
    '''    
    if "[" in string:
        xgconfig.write("contem caractere especial " + string)
        string = string.replace("[","-")
    
    if "]" in string:
        xgconfig.write("contem caractere especial " + string)
        string = string.replace("]","-")
    '''
    if "&" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("&","-")        
        
    if "ç" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("ç","c")
        
    if "ã" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("ã","a")
        
    if "õ" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("õ","o")
    
    if "\\" in string:
        #xgconfig.write("contem caractere especial " + string)
        string = string.replace("\\","-")
    
    if "br*" in string:
        #trata * no final do fqdn
        string = string.replace("br*","br")
    
    if "com*" in string:
        #trata * no final do fqdn
        string = string.replace("com*","br")
      
    return string

def trataInterfaceZone(string):
    if '-' in string:
        string = string.replace("-","")
        
    return string

def clearObjects():
    listVdomObjects.clear()
    #listInterfaceZoneMap.clear()
    listAddressObjects.clear()
    listAddressGroupObjects.clear()
    listServicesObjects.clear()
    listServicesGroupObjects.clear()
    listVirtualIPObjects.clear()
    listVIPGroupObjects.clear()
    listIPpoolObjects.clear()
    listRouteObjects.clear()
    listPolicyObjects.clear()
    listZoneObjects.clear()
            
def printObjects():
    xgconfig.write("<Set>\n")
        
    printInterfaceMAP(listInterfaceZoneMap)
    printAlias(listInterfaceZoneMap)
    printZones(listZoneObjects)
    printRoute(listRouteObjects)    
    printAddress(listAddressObjects)
    printAddressGroup(listAddressGroupObjects)
    printFQDN(listAddressGroupObjects)
    printFQDNGroup(listAddressGroupObjects)
    printServices(listServicesObjects)
    printServiceGroup(listServicesGroupObjects)
    #printIPSECTunnel(listIPSECTunnel)
    
    #gerar alias dos VIPS e ips de interface secundario. necessario?
    #verificar objeto any quando é zona e não mais interface ira liberar para todas interfaces?
    
    printIpsProfile(listPolicyObjects)
    printApplicationProfile(listPolicyObjects)
    printAvProfile(listPolicyObjects)
    printWebFilterProfile(listPolicyObjects)
    printSslProfile(listPolicyObjects)
    
    printPolicy(listPolicyObjects)
    
    xgconfig.write("</Set>\n")
    
    xgconfig.close()
    print("Arquivo Entities.xml criado com sucesso !!!")
    
        
    
def listObjects(fgtconffile):
    filepath = fgtconffile
    #f = open(filepath, encoding="utf8")
    f = open(filepath, encoding="ISO-8859-1")
    
    line = f.readline()
    
    while line:
        if 'config vdom' in line:
            getListVDOM(f)
            
        if 'config system zone' in line:
            getListZones(f)
        
        if 'config firewall address' in line:
            getListAddress(f)

        if 'config firewall addrgrp' in line:
            getListAddressGroup(f)
            
        if 'config firewall service custom' in line:
            getListService(f)
            
        if 'config firewall service group' in line:
            getListServiceGroup(f)
            
        if 'config firewall vipgrp' in line:
            getListVIPGroup(f)
            
        if 'config firewall vip' in line:
             getListVirtualIP(f)
            
        if 'config firewall ippool' in line:
            getListIPpool(f)
            
        if 'config vpn ipsec phase1-interface' in line:
            getListIPESCTunnel(f)
            
        if 'config firewall policy' in line:
            getListPolicy(f)
            
        if 'config router static' in line:
            getListRouterStatic(f)
                            
        line = f.readline()
    
    f.close()
    #return listAddressObjects
    
def main():
    print("""Utilize:
          MigrationTool --fgtconf=<FORTIGATE_CONF.conf> --intmap=<InterfaceZoneMap.csv>\n""")    
    
    if fgtconf == '':
        print("--> Faltou a configuracao do Fortigate")
        
    elif intmap == '':
        print("--> Faltou o arquivo InterfaceZoneMap.csv")
    
    else:        
        intstr = os.path.abspath(intmap)
        loadInterfaceZoneMAP(intstr)
        
        fgtstr = os.path.abspath(fgtconf)
        listObjects(fgtstr)
        
        #print(gvdom)
        #print(vdomMode)
        
        printObjects()
    
    
    #flog.close()
    #fcompare.close()

if __name__ == "__main__":
    main()