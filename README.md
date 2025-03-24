## GetPcapEncrypt-安全协议数据提取器
### 来访人次：
[![Moe Counter](https://count.getloli.com/@GetPcapEncrypt?name=GetPcapEncrypt&theme=moebooru&padding=7&offset=0&align=top&scale=1&pixelated=1&darkmode=auto)](https://github.com/Draina233)  
  
### 功能简介：
从pcap文件获取加密数据、加密套件、证书信息。  
支持TLS协议族(含TLCP)、IPsec ESP(证书解析支持isakmp v1)  
Obtain encryption data, cipher suites, and certificate information from pcap packets.   
Support TLS protocol family (including TLCP), IPsec ESP (certificate resolution supports isakmp v1)  
  
### 使用前准备：
保证tshark相对路径为/wireshark/tshark.exe  
或将tshark添加至环境变量  
Ensure that the relative path of tshark is/wireshark/tshark.exe (configured after decompression)  
Or add tshark to the environment variable  
  
### 使用示例： 
![image](https://github.com/user-attachments/assets/f3074c17-0c4f-46c8-9497-eba355ba0e25)
  
### 更多信息：
Isakmp证书的收集基于udp.payload，在某些场景抓的包可能有预期外的丢失  
开发环境使用wireshark版本为Version 4.2.3 (v4.2.3-0-ga15d7331476c).  
The collection of isakmp cert is based on udp.payload, and packets captured in certain scenarios may have unexpected losses  
The development environment uses Wireshark version 4.2.3 (v4.2.3-0-ga15d7331476c)  
  
**[tshark](https://www.wireshark.org/docs/man-pages/tshark.html)**    **[参考blog](https://www.cnblogs.com/Draina/p/18784550)**  
