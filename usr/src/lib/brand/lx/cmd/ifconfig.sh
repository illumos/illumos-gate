#!/bin/sh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
# 
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.

#
# This script uses the native ifconfig, without the thunk library linked in,
# to display NIC data in the Linux style. The native ifconfig with the thunk
# library cannot be used by non-root users since the thunk library does a
# chroot.
#
# Copyright 2014 Joyent, Inc.  All rights reserved. 
#

short=0
ifname=""

# This is running in Linux, there is likely no getopts command
if [ $# -gt 0 ]; then
    for i in "$@"
    do
        case "$i" in
        "-a") # ignore - interfaces are brought up by the zone
            ;;
        "-s")
            short=1
            ;;
        "-v") # ignore
            ;;
        -*) echo "Error: unsupported option $i"
            exit 1
            ;;
        *)
            if [ -n "$ifname" ]; then
                echo "Error: interface configuration is not supported in a zone"
                exit 1
            fi
            ifname=$i
            ;;
        esac
    done
fi

LD_LIBRARY_PATH_32="/native/lib:/native/usr/lib"
LD_BIND_NOW=1
export LD_LIBRARY_PATH_32 LD_BIND_NOW

# Start by getting the kstats we need
/native/usr/lib/brand/lx/lx_native /native/lib/ld.so.1 \
    /native/usr/bin/kstat -m link -c net | awk '{
    if ($1 == "module:" && length(ifname) > 0)
        printf("%s %s %s %s %s %s %s\n", ifname, ipckts, ierrs, rbytes,
            opckts, oerrs, obytes)

    if ($1 == "name:") ifname=$2
    if ($1 == "ipackets") ipckts=$2
    if ($1 == "ierrors") ierrs=$2
    if ($1 == "rbytes") rbytes=$2
    if ($1 == "opackets") opckts=$2
    if ($1 == "oerrors") oerrs=$2
    if ($1 == "obytes") obytes=$2
} END {
    if (length(ifname) > 0)
        printf("%s %s %s %s %s %s %s\n", ifname, ipckts, ierrs, rbytes,
            opckts, oerrs, obytes)
}' >/tmp/ifstats.$$

/native/usr/lib/brand/lx/lx_native /native/lib/ld.so.1 \
    /native/usr/bin/kstat -m lo -c net | awk '{
    if ($1 == "ipackets") ipckts=$2
    if ($1 == "opackets") opckts=$2
} END {
    printf("lo0 %s 0 0 %s 0 0\n", ipckts, opckts)
}' >>/tmp/ifstats.$$

# Now get the interfaces and format the output
/native/usr/lib/brand/lx/lx_native /native/lib/ld.so.1 /native/sbin/ifconfig |
awk -v pid=$$ -v nm=$ifname -v short=$short 'BEGIN {
    indent="         "
    # load interface kstats
    tfile="/tmp/ifstats." pid
    while (getline < tfile > 0) {
        stats[$1]=substr($0, length($1) + 2)
    }

    if (short)
        printf("%s   %s %s   %s %s %s %s    %s %s %s %s %s\n", "Iface", "MTU",
            "Met", "RX-OK", "RX-ERR", "RX-DRP", "RX-OVR", "TX-OK", "TX-ERR",
            "TX-DRP", "TX-OVR", "Flg")
}

function fmt() {
    if (length(nm) > 0 && ifname != nm)
        return

    if (ifname == "lo0") {
        encap="Local Loopback"
        qlen=0
        sflg="LRU"
    } else {
        encap="Ethernet"
        qlen=1000
        sflg="BMRU"
    }

    n = split(stats[ifname], s)
    if (n != 6)
        s[1] = s[2] = s[3] = s[4] = s[5] = s[6] = 0

    if (short) {
        printf("%-5s %5s %3s   %5s %6s %6s %6s    %5s %6s %6s %6s %s\n",
            ifname, mtu, 0, s[1], s[2], 0, 0, s[4], s[5], 0, 0, sflg)
        return
    }

    printf("%-9s Link encap:%s", ifname, encap)
    if (length(enetaddr) > 0)
        printf("  HWaddr %s", enetaddr)
    printf("\n")
    printf("%9s inet addr:%s", indent, inet)
    if (length(bcast) > 0)
        printf("  Bcast:%s", bcast)
    printf("  Mask:%s\n", mask)
    printf("%9s %s  MTU:%s\n", indent, flags, mtu)
    printf("%9s RX packets:%s errors:%s dropped:0 overruns:0 frame:0\n",
        indent, s[1], s[2])
    printf("%9s TX packets:%s errors:%s dropped:0 overruns:0 carrier:0\n",
        indent, s[4], s[6])
    printf("%9s collisons:0 txqueuelen:%s\n", indent, qlen)
    printf("%9s RX bytes:%s  TX bytes:%s\n", indent, s[3], s[6])
    printf("\n")
}

{
    if (substr($1, length($1), 1) == ":") {
        if (length(ifname) > 0) {
            # print prev entry and reset
            fmt()
            ifname=""
            bcast=""
            enetaddr=""
        }

        ifname=substr($1, 1, length($1) - 1)
        mtu=$4
        pos=index($2, "<") + 1
        flags=substr($2, pos, length($2) - pos)
	getline
        inet=$2
        mask=$4
        if (NF > 4)
            bcast=$6
        else
            bcast=""
    } else if ($1 == "ether") {
        enetaddr=$2
    }
}

END {
        if (length(ifname) > 0) {
            fmt()
        }
}'

rm -f /tmp/ifstats.$$
