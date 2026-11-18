# Arti Showcase

This page serves as a collection of projects, originating from within the Tor
Project as well as externally, that utilize Arti in one way or another,
preferably as a Rust library.

Keep in mind that this list is not exhaustive, nor does it imply any sort of
endorsement or affiliation with the Tor Project.

If you have done something cool with Arti, we would love to hear about it!
Feel free to open a merge request expanding this list or let us know in our
`#tor-dev` IRC channel.

<!-- Please keep this list sorted alphabetically -->

## Halloy

[*Halloy*](https://halloy.chat/) is a modern open-source IRC client written in
Rust that supports using [Arti](https://halloy.chat/configuration/proxy#tor) as
a native proxy option and an alternative to SOCKS5 and HTTP based proxies.

## oniux

[*oniux*](https://gitlab.torproject.org/tpo/core/oniux) is a tool that utilizes
various Linux `namespaces(7)` features in order to isolate arbitrary
applications over the Tor network by providing a TUN interface that tunnels all
TCP traffic through Tor.  The driver for the TUN interface, *onionmasq*, uses
Arti and smoltcp to wrap TCP streams to Tor streams.

## Tor VPN Beta

[*Tor VPN Beta*](https://support.torproject.org/tor-vpn/) is an Android
application that routes apps on a device through the Tor network.  A unique
aspect is that every application gets it's own Tor circuit, thereby improving
the overall privacy compared to a conventional VPN application.  Similarly to
oniux, it also uses *onionmasq* to achieve this.
