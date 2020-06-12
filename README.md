# napt
NAPT - Network Address Port Translation & IP Forwarding

## System requirements

- [VirtualBox](https://www.virtualbox.org/)
- [Vagrant](https://www.vagrantup.com/)

## Setup

Build the `corevm` virtual machine by:

```bash
$ vagrant up
...
```

It's gonna take few minutes if you're running it for the first time. When it's done, just check the virtual machine status by:

```bash
$ vagrant status
...
corevm                    running (virtualbox)
...
```

## Launching

If `corevm` virtual machine isn't running, just follow the steps on the [Setup section](#setup). Otherwise, just ssh to it and open the core application.

```bash
$ vagrant ssh
vagrant@corevm:~$ sudo /etc/init.d/core-daemon start
starting core-daemon
vagrant@corevm:~$ core-gui
Connecting to "core-daemon" (127.0.0.1:4038)...connected.
```

## Exiting

If you're running `core-gui`, then your terminal window should be looking like this:


```bash
vagrant@corevm:~$ core-gui
Connecting to "core-daemon" (127.0.0.1:4038)...connected.
```

On `core-gui` window click on File and then click on Quit. On the terminal window, it should display the connection to the core-daemon is closed. Now you should be able to run `exit` inside `corevm` and then halt the virtual machine.

```bash
Connection to "core-daemon" (127.0.0.1:4038) closed.
vagrant@corevm:~$ exit
$ vagrant halt
```

To be sure if `corevm` virtual machine is down just check its status by:

```bash
$ vagrant status
...
corevm                    poweroff (virtualbox)
...
```

## Loading topology

On `core-gui` window click on File, then click on Open and then navigate to `/vagrant` directory and select `topology.imn`/`topology.xml` file.

## Topology

There are two networks on this topology: the private and the public one. By definition, hosts on the public network (10.0.1.0/24) can't send packets directly to hosts inside the private network (10.0.0.0/24). The hosts in the public network must send packets to the NAT router `n2`. The router will forward it to the private hosts. The private hosts, on the other hand, can send packets to hosts in the public network, but their private IP addresses are replaced by the NAT router's public IP address.

## Simulation

First, to prevent the reply of [RST packets on TCP connections](https://tools.ietf.org/html/rfc793) when the port's state on the TCP header is not with the OPEN state, run the following command on a new bash window on the Router `n2`: 

```bash
$ iptables -I OUTPUT -p tcp --tcp-flags ALL RST -j DROP
```

Then, run the Python NAPT script by:

```bash
$ cd /vagrant
$ python3 nat.py
```

### ICMP

Since the host `n1` (10.0.0.10/24) is in the private network, by running a ping command to the public host `n3` (10.0.1.11/24) you should be able to monitor on Wireshark that the outgoing ICMP packets from router `n2` has the router IP address as source IP address instead of `n1`'s. Once `n3` replies, it's possible to notice the target IP address is `n2`'s. When `n2` receives the reply, it forwards it to `n1` which acknowledges it.

### TCP & UDP

You can also run a TCP/UDP server on a public host and a TCP/UDP client on a private one. For example, you can launch a server on `n3` on port 6000 by:

```bash
# UDP
$ python3 echo_server_udp.py --port 6000

# TCP
$ python3 echo_server_tcp.py --port 6000
```

And a client on `n1` by:

```bash
# UDP
$ python3 echo_client_udp.py --port 6000

# TCP
$ python3 echo_client_tcp.py --port 6000
```

A similar behavior as mentioned in [ICMP section](#icmp) happens here, where the server receives forwarded packets from `n1` via `n2` and replies to them.

## Implementation

The `nat.py` Python script sniffs all packets coming through `eth0` and `eth1` network interfaces and filters for further processing only IP packets matching the following requirements:

- Its protocol must be the ICMP, TCP or UDP.
- Incoming packets on `eth1` network interface must not have a target IP address from the private network (10.0.0.0/24).

After this filtering, the script does the IP forwarding of packets coming through the router and, similar to NAT, masks the outgoing packet's source IP address with the router's public address. For TCP & UDP packets, the router running the `nat.py` script simply uses the same port as the private host's TCP/UDP client. The router will simply send a forwarded raw packet to the TCP/UDP server.

## Limitations

The current implementation is not scalable. It means it's not currently possible to have more than one private host and more than one public host. Also, the NAPT script doesn't support dynamic MAC and IP addresses. For this reason, some MAC and IP addresses are hardcoded on `nat.py` file.


### ICMP

There's an unexpected behavior when the public host sends an ICMP echo request to the NAPT router public address where the ICMP echo reply is duplicated. It happens because both router and private host are replying that request. Further processing on ICMP packets would be necessary to provent it from happening.

### TCP & UDP

The TCP & UDP scripts have the server IP address hardcoded. If you happen to need to change it, be aware to update the MAC or IP addresses on the NAPT script. When testing the UDP client-server, you may happen to notice an ICMP destination unreachable packet due an unhandled behavior where there's no UDP open port. However, it won't cause any issues on the TCP/UDP client-server communication though.

## Demo

[![Simulation Video](https://img.youtube.com/vi/opXbkZ98XWE/0.jpg)](https://www.youtube.com/watch?v=opXbkZ98XWE)
