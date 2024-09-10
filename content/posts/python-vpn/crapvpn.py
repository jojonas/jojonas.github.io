#!/usr/bin/env python3

from fcntl import ioctl
import select
import socket
import struct
import subprocess
import typing

import click


def open_tun_device(device_name: str = "tun0") -> typing.BinaryIO:
    """Open a TUN device with the given name"""

    # snippet:start open_tun
    name_bytes = device_name.encode()
    assert len(name_bytes) < 16, "The interface name must be less than 16 bytes"

    tuntap = open("/dev/net/tun", "r+b", buffering=0)

    LINUX_IFF_TUN = 0x0001
    LINUX_IFF_NO_PI = 0x1000
    flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
    ifs = struct.pack("16sH22s", name_bytes, flags, b"")

    LINUX_TUNSETIFF = 0x400454CA
    ioctl(tuntap, LINUX_TUNSETIFF, ifs)
    # snippet:end open_tun

    return tuntap


def configure_tun_device(device_name: str, local_ip: str, peer_ip: str):
    """Configure the IP address and peer on a given network device"""

    # snippet:start configure_tun
    subprocess.run(("ip", "link", "set", device_name, "up"), check=True)
    subprocess.run(
        ("ip", "addr", "add", local_ip, "peer", peer_ip, "dev", device_name),
        check=True,
    )
    # snippet:end configure_tun


# snippet:start xor
def xor(data: bytes, key: bytes):
    """XOR two byte arrays, repeating the key"""
    retval = bytearray(data)
    for i, _ in enumerate(data):
        retval[i] = data[i] ^ key[i % len(key)]
    return bytes(retval)
    # snippet:end xor


# snippet:start vpn
CRAPVPN_HEADER = ">4sHxx"
CRAPVPN_MAGIC = b"crap"
CRAPVPN_HEADER_SIZE = struct.calcsize(CRAPVPN_HEADER)


def prepare_data_for_sending(data: bytes, key: bytes) -> bytes:
    """Encrypt and wrap data for sending via the VPN"""
    ciphertext = xor(data, key)
    return struct.pack(CRAPVPN_HEADER, CRAPVPN_MAGIC, len(ciphertext)) + ciphertext


def handle_received_data(data: bytes, key: bytes) -> bytes | None:
    """Unwrap and decrypt data from the VPN"""
    magic, length = struct.unpack(CRAPVPN_HEADER, data[:CRAPVPN_HEADER_SIZE])

    if magic != CRAPVPN_MAGIC:
        return None

    ciphertext = data[CRAPVPN_HEADER_SIZE:]
    if len(ciphertext) != length:
        return None

    plaintext = xor(ciphertext, key)
    return plaintext
    # snippet:end vpn


def run(
    listen_address: tuple[str, int],
    local_ip: str,
    peer_address: tuple[str, int],
    peer_ip: str,
    key: bytes,
):
    """Run the VPN service"""

    # Open TUN device
    device_name = "tun0"
    tuntap = open_tun_device("tun0")

    # Bring device up, configure IP address and route
    configure_tun_device(device_name, local_ip, peer_ip)

    # snippet:start open_socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as remote:
        remote.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        remote.bind(listen_address)

        # snippet:end open_socket
        # snippet:start main_loop
        while True:
            rd_sockets, _, _ = select.select([tuntap, remote], [], [], 1.0)

            for sock in rd_sockets:
                if sock is tuntap:
                    # Data from TUNTAP needs to be pumped to the peer
                    data = tuntap.read(0xFFFF)
                    data = prepare_data_for_sending(data, key)
                    remote.sendto(data, peer_address)

                elif sock is remote:
                    # Data from the peer needs to be pumped to TUNTAP
                    data = remote.recv(0xFFFF)
                    data = handle_received_data(data, key)
                    if data:
                        tuntap.write(data)
    # snippet:end main_loop


@click.command()
@click.option("-k", "--hex-key", required=True, help="Encryption key (hex encoded)")
@click.option("-p", "--peer-host", required=True)
@click.argument("local-ip")
@click.argument("peer-ip")
def main(
    hex_key: str,
    peer_host: str,
    local_ip: str,
    peer_ip: str,
):
    """CrapVPN - a demo VPN implementation by Jonas Lieb (github.com/jojonas)

    See jonaslieb.de/blog/crapvpn/ for details.
    """

    run(
        listen_address=("", 1337),
        peer_address=(peer_host, 1337),
        local_ip=local_ip,
        peer_ip=peer_ip,
        key=bytes.fromhex(hex_key),
    )


if __name__ == "__main__":
    main()
