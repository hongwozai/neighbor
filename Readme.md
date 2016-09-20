Neighbor
============================================

neighbor v1.0

written by James Lu.

-a  		向网络中每一台机器都发送arp请求包，生成arp cache，并输出 

-p: 		指定机器ip进行探测，不能与-a共存

-t: 		设定超时时间

-m: 		设定主机mac地址，不设定则为默认接口的mac

-l: 		设定主机ip地址，不设定则为默认接口的ip

-n: 		设定子网掩码，只用输入位数即可

-i: 		设定接口，默认eth0

-v  		verbose

-q: 		arp缓存投毒的目标ip

-g: 		arp缓存投毒的网关ip


eg. 
1.发包时更改本地主机与网卡mac（伪造），应与其余功能一起使用

	neighbor -i eth0 -l 192.168.100.56 -m ff:ff:ff:ff:ff:ff -n 24

2.探测子网内主机mac

	neighbor -a

3.探测指定主机的mac

	neighbor -p 192.168.100.53

4.arp缓存投毒

	neighbor -q 192.168.100.53 -g 192.168.103.1

5.设定发包之后收包的超时时间，以ms为单位

	neighbor -t 100

6.调试输出

	neighbor -v

