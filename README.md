dnscache
========

a small DNS forwarder, with caching functionality.
it's purpose is mainly to be used as a so-called `pihole`, but without requiring
to run a docker container, a separate box, or somesuch.
it was devised because all existing and known (by me) solutions are either
difficult to set up, bloated, or buggy.

usecase 1: caching DNS server for your own box
----------------------------------------------
in case you got a slow internet connection, having DNS names cached can make
a huge performance difference, and also makes your internet usage less
transparent to the provider of your DNS server, as every DNS name is only
looked up once during the lifetime of the process.
in this case you probably want to either run dnscache on port 53 as root,
or redirect port 53 to whatever port you run dnscache on, and put it as your
nameserver into `/etc/resolv.conf`.
as dnscache has only a few hundred lines of code it should be quite easy to
assure that it's not exploitable.

usecase 2: prevent connections to undesired domains
---------------------------------------------------
dnscache accepts an option -l to specify an `/etc/hosts`-style ip/dns mapping
which is loaded on start, and additionally an option -s to specify a script
that gets passed a yet unknown DNS name and can return an IP for it.
this makes it easy to write a small script/program that matches the hostname
using e.g. a regex against common naming patterns for adservers or devices
that "call home" like e.g. android devices that talk to google servers all the
time even when no google app is actively being used, probably telling them all
sorts of stuff about your behaviour, interests, data, and usage patterns.
a couple lines in the list file or some custom rules in a matcher script make
a quick end to this unwanted behaviour.
to make this work, you need to control the internet gateway used by those
devices e.g. when you run `hostapd` on your local box, and define some iptables
rules to bend traffic to dnscache.
in case of running this on a NAT router, you'd configure some rules roughly
like this:

       iptables -t nat -A PREROUTING -i OUTIF -p udp --dport 53 \
         --source HOST -j DNAT --to ADDR:PORT

where

    OUTIF = network interface where you want to capture DNS requests
    HOST  = the ipv4 of the host of which we want to hijack DNS request
    ADDR  = ipv4 address of dnscache listen interface (e.g. 127.0.0.1)
    PORT  = port where dnscache listens

this example would redirect all DNS packets of HOST to our dnscache.

to catch traffic of e.g. a virtual machine running on your box, you'd need
to use the `OUTPUT` chain instead of `PREROUTING`. in that case it's a little
trickier to not make looping DNS requests. what i did is to specify a DNS
server ip for use with dnscache that's not used anywhere else on the system
(and is not google's DNS server either), then make the rule like so:

    iptables -t nat -A OUTPUT -p udp --dport 53 \
     ! --destination A.B.C.D -j DNAT --to 127.0.0.1:2053

where A.B.C.D is the address of that DNS servers. this tells iptables to let
only DNS requests to that specific server go out.

you can check your rules like so:

    iptables -t nat -L --line-numbers

this will show you the rules for chains `OUTPUT` and `PREROUTING` with
linenumbers, which can be used with the command

    iptables -t nat -D CHAINNAME N

where N is that linenumber.


implementation details
----------------------

dnscache works currently only with ipv4. if an AAAA (ipv6) request is received,
the request will be turned into an A (ipv4) request and forwarded to the
chosen upstream DNS server. the returned ipv4 is then converted into an
ipv4-in-ipv6 address and returned to the client.
currently the implementation is quite lame in that only one thread is used,
so while an upstream DNS lookup is in progress, the server blocks.
also MX lookups aren't currently processed.
otoh the implementation is quite resource efficient, only a couple bytes are
required for every cached DNS name. while no DNS packets are received, there
is no CPU usage at all. it's estimated that this daemon can run for weeks and
never consume more than like 256KB heap memory.
the best of all is that no config file is necessary, everything can be done
with a handful of command line options.
