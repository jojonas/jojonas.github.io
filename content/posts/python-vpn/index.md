+++ 
date = 2024-08-25T15:07:00+02:00
title = "A Simple VPN in Python"
+++

In this post I want to provide an annotated template for implementing tunneling protocols in Python. In the process, I want to familiarize you with a couple of core concepts such as tunneling, TUN/TAP interfaces and packet encapsulation. Also, this post will be the first in a multipart series, as I will be demonstrating how to analyze tunneling protocols in Wireshark in the latter parts.

<!--more-->

So what is a VPN exactly? Practically speaking, a VPN is a technology that allows to transport (or _tunnel_) network traffic from one system to another: Packets enter the tunnel on one end and exit on the other end. That's it, and it will not modify anything! However, it protects your data in transit between both tunnel ends, by encrypting the network packet bytes and wrapping the ciphertext in larger packets. This process is called _encapsulation_.

## TUN/TAP Devices

A very common way of entering (and exiting) the tunnel is a _virtual network adapter_. Its greatest advantage is that one can apply tools and concepts also commonly used with _physical_ network adapters. On Linux there are (at least) two kinds of tunneling adapters: TUN and TAP devices. TUN devices operate on layer 3 of the OSI model, the network layer. The most common layer-3 protocols are IPv4 and IPv6. This means that TUN devices can ingest and emit IP packets, but not Ethernet frames. Network devices on both ends of the tunnel can communicate via IP routing, but are not in the same LAN. Tunneling Ethernet frames can be achieved with a TAP device, which operates on layer 2. While this allows systems to reach each other via broadcast, it also results overhead in terms of performance and complexity[^1]. Therefore, this post will focus on layer-3 implementations.

[^1]: More on the advantages and disadvantages of TUN and TAP devices can be found in the [OpenVPN wiki](https://community.openvpn.net/openvpn/wiki/BridgingAndRouting).

Only a few lines of Python code are required to create a TUN device (taken from [this blog post by Julia Evans](https://jvns.ca/blog/2022/09/06/send-network-packets-python-tun-tap/)):

```python
device_name = "tun0"
```

{{< code language="python" source="crapvpn.py" id="open_tun" dedent=4 >}}

The function returns a file-like object, i.e. you can call `read()` and `write(...)` on it. Linux by default does not assign an IP address, nor any routes to this interface. The following lines use the `ip` command to configure the device in the peer-to-peer configuration:

{{< code language="python" source="crapvpn.py" id="configure_tun" dedent=4 >}}

In addition to the local TUN interface, the VPN needs a socket to connect to the remote peer (e.g. via the Internet). For a UDP-based VPN, the code is symetrical on both peers:

{{< code language="python" source="crapvpn.py" id="open_socket" dedent=4 >}}

## VPN Main Loop

Once both the local TUN interface and the remote socket are set up, the centerpiece can be implemented: A main loop that _simultaneously_ reads packets from the TUN adapter and forwards them via the VPN while also reading packets from the VPN to emit them at the TUN interface. This is a perfect application for the `select` system call:

{{< code language="python" source="crapvpn.py" id="main_loop" options="hl_lines=2" dedent=4 >}}

During each iteration of the `while` loop, `select` will return the socket that has data available for reading (if any). The code reads the data and processes it.

## Encapsulation

As described earlier, the packets need to be wrapped and optionally encrypted. My implementation uses [XOR "encryption"](https://en.wikipedia.org/wiki/XOR_cipher) with a static, repeating key (hence the name _CrapVPN_):

{{< code language="python" source="crapvpn.py" id="xor" >}}

The following diagram shows the encapsulation format:

```goat {width=700}
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Magic (4 bytes)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Length (2 bytes)       |       Reserved (2 bytes)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                  Ciphertext (variable length)                 +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```


The entire encapsulation can be implemented with the following two functions:

{{< code language="python" source="crapvpn.py" id="vpn" >}}

## Putting It All Together

At this point all central components for the VPN service are done. Here's the full source code, also available as download [here](crapvpn.py):

<details>
<summary>Full Source Code</summary>
{{< code language="python" source="crapvpn.py" options="linenos=inline" >}}
</details>

### Running the VPN Client

The full version has a command-line interface that accepts the key, the remote peer's IP address and the addresses to be configured inside the tunnel. It can be used as follows...

Host A:

```shell-session
$ sudo ./crapvpn.py -k 1234ABCD -p <Host_B_IP> 192.168.2.1 192.168.2.2
```

Host B:

```shell-session
$ sudo ./crapvpn.py -k 1234ABCD -p <Host_A_IP> 192.168.2.2 192.168.2.1
```

Then you should be able to send data from the host `192.168.2.1` to host `192.168.2.2` and vice versa, for example by sending an ICMP echo request:

```shell-session
$ ping -c 3 192.168.2.2
PING 192.168.2.2 (192.168.2.2) 56(84) bytes of data.
64 bytes from 192.168.2.2: icmp_seq=1 ttl=64 time=0.625 ms
64 bytes from 192.168.2.2: icmp_seq=2 ttl=64 time=0.697 ms
64 bytes from 192.168.2.2: icmp_seq=3 ttl=64 time=0.623 ms

--- 192.168.2.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2006ms
rtt min/avg/max/mdev = 0.623/0.648/0.697/0.034 ms
```

```shell-session
$ curl -I http://192.168.2.2:8000/      
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.9
Date: Sun, 25 Aug 2024 17:54:13 GMT
Content-type: text/html; charset=utf-8
Content-Length: 652
```

## Conclusion

It is very easy to implement a VPN in Python using TUN/TAP devices. The centerpiece is a main-loop that simultaneously handles packets going in both directions. The code I presented is supposed to act as a template for learning and for tinkering with unknown encapsulation protocols. Here are some ideas, in which the code can be adapted:
 * switch to a layer-2 VPN (if you need it)
 * implement tunneling over TCP (not recommended, but still necessary sometimes)
 * improve encryption (ideally you would use an [AEAD cipher](https://en.wikipedia.org/wiki/Authenticated_encryption))

I will use this implementation in the [next blog post](/blog/wireshark-vpn/), where I will demonstrate how to modify Wireshark to support CrapVPN.