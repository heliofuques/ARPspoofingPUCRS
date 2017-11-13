# ARPspoofingPUCRS
Project made to the class "Computer Networking"


Mininet download:
```
sudo apt-get install mininet
```
Starting mininet
```
sudo mn --mac --topo single,3 
```
Configure hosts
```
mininet> h1 ifconfig h1-eth0 inet6 add fc00::1/64
mininet> h2 ifconfig h2-eth0 inet6 add fc00::2/64
mininet> h2 ifconfig h2-eth0 inet6 add fc00::3/64
```
Ping
```
mininet> h1 ping6 fc00::2 -I h1-eth0
```

# Enter in SSH connection betwwen two hosts using a IPV6 connection

Execute the SSH example
```
sudo python mininetSSHserver.py 
```

Configure hosts as the example above. And uses the ssh conection with the -6 flag following the IPV6 address.

```
h1 ssh -6 root@fc00::2
```
You can see the communication in the wireshark now.

# Using ARPSpoofing in a IPV4 connection

Install dsniff
```
sudo apt-get install dsniff
```

Execute the mininetSSHserver.py

Execute the arpspoofing program in the mininet.
Command template:
```
arpspoof -i <INTERFACE> -t <IP_DO_ALVO> <IP_QUE_SEU_ALVO_VAI_MAPEAR_PARA_SEU_MAC>
```

Command example in mininet:
```
h1 arpspoof -i eth0 -t h1 h4
```