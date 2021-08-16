#!/usr/local/bin/python3.8
import re
import sys
import csv
import itertools

with open(sys.argv[1],'r') as file:
    lines = file.readlines()

end_tag=('</C T="[78]')

pairs = {'CallDuration':'T="[14]"','userLocationInformation':'T="[8]" TL="2" V="13"','servedMSISDN':'P T="[22]" TL="2"','servedIMEISV':
       'T="[29]" TL="2"','recordOpeningTime':'T="[13]"','servedPDPPDNAddress':'T="[9]" TL="2" V="8"','accessPointNameNI':'T="[7]" TL="2" V="9"'}

vip_data=dict(CallDuration=list(),userLocationInformation=list(),servedMSISDN=list(),servedIMEISV=list(),recordOpeningTime=list(),
             servedPDPPDNAddress=list(),accessPointNameNI=list())

for line in range(len(lines)):
    if end_tag in lines[line]:
        continue

    elif pairs['CallDuration'] in lines[line]:
        a=re.findall('&#x(.*?);',lines[line])
        dec=str(int(''.join(a),16)) # Note: Decimal string
        vip_data['CallDuration'].append(dec)

        #location_parser
    elif pairs['userLocationInformation'] in lines[line]:
        a=re.findall('&#x(.*?);',lines[line])
        a=''.join(a)
        pattern=a[-7:][0:5]+'-'+a[-2:]
        a=pattern.split('-')
        location='-'.join([str(int(i,16)) for i in a])
        vip_data['userLocationInformation'].append(location)

    #call_num_parser   
    elif pairs['servedMSISDN'] in lines[line]:
        a=re.findall('&#x(.*?);',lines[line])
        raw=''.join(a)[2:]
        call=''.join([raw[char:char+2][::-1] for char in range(0, len(raw), 2) if len(raw)%2==0])
        vip_data['servedMSISDN'].append(call)

        #imei_parser  
    elif pairs['servedIMEISV'] in lines[line]:
        imei_pattern=[1,0,3,2,5,4,7,6,9,8,11,10,13,12]
        a=re.findall('&#x(.*?);',lines[line])
        a=''.join(a)
        joined_list=list(map(a.__getitem__, imei_pattern))
        imei=''.join(joined_list)+'0' #adding zero at the end of string
        vip_data['servedIMEISV'].append(imei)

    #timestamp_parser
    elif pairs['recordOpeningTime'] in lines[line]:
        a=re.findall('&#x(.*?);',lines[line])
        a=''.join(a)[0:12]
        vip_data['recordOpeningTime'].append(a)

    #IP parser
    elif pairs['servedPDPPDNAddress'] in lines[line]:
        a=re.findall('&#x(.*?);',lines[line+2])
        raw_ip=[str(int(num,16)) for num in a]
        ip='.'.join(raw_ip)
        vip_data['servedPDPPDNAddress'].append(ip)


    elif pairs['accessPointNameNI'] in lines[line]:
        b=re.findall('&#x(.*?);',lines[line])
        b=''.join(b)
        b=bytearray.fromhex(b).decode()
        vip_data['accessPointNameNI'].append(b)

with open("test.csv", "w") as outfile:
    writer = csv.writer(outfile)
    writer.writerow(vip_data.keys())
    writer.writerows(itertools.zip_longest(*vip_data.values()))
