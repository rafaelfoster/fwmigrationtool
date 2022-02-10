import sys
import os

filepath = ''

for param in sys.argv :
    if '--fgtconf' in param:
        filepath = param.replace("--fgtconf=","")
        filepath = os.path.abspath(filepath)
        
print("""Utilize:
          
InterfaceZoneMap --fgtconf=<FORTIGATE_CONF.conf>\n""")



def listinterface(f,f2write):
    
    f2write.write("Fgt Interface Name,Fgt Interface Ips,Fgt Type Interface, Fgt Vlan ID , Fgt Vlan/Lag Interface, Fgt VDOM, XG Interface Name, XG Interface Ips, XG Type Interface, XG Vlan ID, XG Vlan/Lag Interface, XG Zone\n")
    
    line = f.readline()
    
    stop = 'end'
    
    name = ''
    listIpintf = []
    ipintf = ''
    typeintf = 'VLAN'
    vlanid = '0'
    vlanlagint = ''
    vdom = 'root'
   
    while line:
        
        line = line.strip()
       
        if 'set vdom' in line:
            vdom = line.replace("set vdom \"","")
            vdom = vdom.replace("\"","")
        
        if 'config secondaryip' in line:
            
            while 'end' not in line:
                
                line = line.strip()
                
                if 'set ip' in line:
                    aipintf = line.replace("set ip ","")
                    aipintf = aipintf.replace(" ","/")
                    ipintf = ipintf + ";s=" + aipintf
                    
                line = f.readline()      

        if 'edit' in line:
            aname = line.replace("edit \"","")
            name = aname.replace("\"","")

        if 'set ip' in line:
            aipintf = line.replace("set ip ","")
            aipintf = aipintf.replace(" ","/")
            listIpintf.append("p=" + aipintf)
            ipintf = "p=" + aipintf
        
        if 'set vlanid' in line:
            vlanid = line.replace("set vlanid ","")
                       
        
        if 'set type' in line:
            atype = line.replace("set type ","")
            typeintf = atype
            
        if 'set interface' in line:
            avlanlagint = line.replace("set interface ", "")
            avlanlagint = avlanlagint.replace("\"","")
            vlanlagint = avlanlagint
            
        if 'set member' in line:
            avlanlagint = line.replace("set member \"", "")
            avlanlagint = avlanlagint.replace("\"","")
            avlanlagint = avlanlagint.replace(" ",";")
            vlanlagint = avlanlagint
        
            
                
        if line=='next':
            #print(name + ",[" + ipintf + "]," + typeintf +"," +vlanid + ",[" + vlanlagint +"],"+name+",[" + ipintf + "],"+typeintf+","+vlanid+", XG vlan/lag Interfaces, XG Zone")
            f2write.write(name + ",[" + ipintf + "]," + typeintf +"," +vlanid + ",[" + vlanlagint +"],"+vdom+","+name+",[" + ipintf + "],"+typeintf+","+vlanid+", XG vlan/lag Interfaces,XG Zone\n")
            name = ''
            ipintf = ''
            typeintf = 'VLAN'
            vlanid = '0'
            vlanlagint = ''
            vdom = 'root'

        if line==stop:
            break
        
        line = f.readline()

def main():
    
    if filepath == '':
        print("-> Fornecer o arquivo de configuracao")
        
    else:
        #f = open(filepath, encoding="utf-8")
        f = open(filepath, encoding="ISO-8859-1")
        f2write = open("InterfaceZoneMap.csv", "w")
    
        line = f.readline()
        
        while line:
            if 'config system interface' in line:
                listinterface(f, f2write)
                break
            
            line = f.readline()
               
        print("-> Feito! arquivo InterfaceZoneMap.csv gerado, favor preencher!")
        f.close()
        f2write.close()

if __name__ == "__main__":
    main() 
           

