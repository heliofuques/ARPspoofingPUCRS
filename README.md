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
