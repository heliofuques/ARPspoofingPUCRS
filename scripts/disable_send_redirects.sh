for i in `ls -1 /proc/sys/net/ipv4/conf/*/send_redirects`; do echo 1 > $i; done
