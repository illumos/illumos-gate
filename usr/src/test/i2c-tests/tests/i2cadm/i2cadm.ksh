#!/usr/bin/ksh
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

#
# Copyright 2025 Oxide Computer Company
#

#
# Test functionality of i2cadm against the automatically set up tree. This
# generally covers bad arguments, good and bad filters, and ofmt. Positive
# tests for performing io and scanning are in separate programs.
#

. $(dirname $0)/common.ksh

#
# Bad arguments to the program
#
i2cadm_fail
i2cadm_fail controller
i2cadm_fail controller foobar
i2cadm_fail controller help
i2cadm_fail controller 123
i2cadm_fail controller list -wat
i2cadm_fail controller list -o
i2cadm_fail controller list -o foobar
i2cadm_fail controller list -p
i2cadm_fail controller prop get
i2cadm_fail controller prop get -p i2csim0
i2cadm_fail controller prop get -H -p i2csim0
i2cadm_fail controller prop get -H -p i2csim0
i2cadm_fail controller prop get -o foo i2csim0
i2cadm_fail controller prop get -o foo
i2cadm_fail controller prop set
i2cadm_fail controller prop set speed
i2cadm_fail controller prop set i2csim0
i2cadm_fail controller prop set i2csim0 speed
i2cadm_fail controller prop set i2csim0 speed=
i2cadm_fail controller prop set i2csim0 i2c-max-read=0x
i2cadm_fail controller prop set i2csim0 i2c-max-read=nope
i2cadm_fail controller prop set i2csim0 i2c-max-read=0x2nope
i2cadm_fail controller prop set i2csim0 i2c-max-read=42answer
i2cadm_fail device
i2cadm_fail device help
i2cadm_fail device sephiroth
i2cadm_fail device list cloud
i2cadm_fail device list -o
i2cadm_fail device list -o aerith
i2cadm_fail device list -o aerith i2csim0
i2cadm_fail device list -p
i2cadm_fail device addrs cloud
i2cadm_fail device addrs -o
i2cadm_fail device addrs -o aerith
i2cadm_fail device addrs -o aerith i2csim0
i2cadm_fail device addrs -p
i2cadm_fail device add
i2cadm_fail device add i2csim0/0
i2cadm_fail device add i2csim0/0 foobar
i2cadm_fail device add i2csim0/0 foobar 0x11 trailing
i2cadm_fail device add i2csim0/0 foo@bar 0x11
i2cadm_fail device add i2csim0/0 1oobar 0x11
i2cadm_fail device add i2csim0/0 foo^bar% 0x11
i2cadm_fail device add i2csim0/0 'foo bar' 0x11
i2cadm_fail device add i2csim0 foobar 0x11
i2cadm_fail device add i2csim0/0/0x20 foobar 0x11
i2cadm_fail device remove
i2cadm_fail device remove i2csim0
i2cadm_fail device remove i2csim0/0
i2cadm_fail device remove i2csim0/23
i2cadm_fail device remove i2csim0/0/0x11
i2cadm_fail device remove i2csim0/0/0x70/0/0x11
i2cadm_fail device remove i2csim0/0x10
i2cadm_fail device remove i2csim0/23/0x10
i2cadm_fail device remove i2csim0/0/0x10 extra
i2cadm_fail mux
i2cadm_fail mux cid
i2cadm_fail mux list -o
i2cadm_fail mux list -o tifa
i2cadm_fail mux list -o tifa i2csim0
i2cadm_fail mux list -p
i2cadm_fail port
i2cadm_fail port vincent
i2cadm_fail port list -o
i2cadm_fail port list -o red13
i2cadm_fail port list -o red13 i2csim0
i2cadm_fail port list -p
i2cadm_fail port map
i2cadm_fail port map -p i2csim0/0
i2cadm_fail port map -o foo i2csim0/0
i2cadm_fail port map -p -o foo
i2cadm_fail port map -p -o type
i2cadm_fail port map -wtf i2csim0/0
i2cadm_fail port map i2csim0
i2cadm_fail port map i2csim0/23
i2cadm_fail port map i2csim0/0/0x10
i2cadm_fail port map i2csim0/0/0x70
i2cadm_fail port map i2csim0/0/0x70/0/0x71
i2cadm_fail io
i2cadm_fail io i2csim0/0
i2cadm_fail io -m i2c
i2cadm_fail io -m i2c -a 0x20
i2cadm_fail io -m i2c -d i2csim0/0/0x10 -r hello
i2cadm_fail io -m i2c -d i2csim0/0/0x10 -r 0x7777
i2cadm_fail io -m i2c -d i2csim0/0 -a 0x10 -r hello
i2cadm_fail io -m i2c -d i2csim0/0 -a 0x10 -r 0x7777
i2cadm_fail io -m i2c -c 0x23 -a 0x10 -r 0x4 -w 2 0x00 0x00
i2cadm_fail io -m read-u8 -d i2csim0/0/x20
i2cadm_fail io -m recv-u8 -c 0x23 -d i2csim0/0/0x20
i2cadm_fail io -d i2csim0/0 -r 2 -w 1 0x00
i2cadm_fail io -d i2csim0/0/x20 -r 2 -w 1 0x00
i2cadm_fail io -d i2csim0/0/0x20
i2cadm_fail io -d i2csim0/0/0x20 -w 1
i2cadm_fail scan
i2cadm_fail scan -p
i2cadm_fail scan -p -o addr,result
i2cadm_fail scan -p i2csim0/0
i2cadm_fail scan -c i2csim0/0
i2cadm_fail scan -d foobar i2csim0/0
i2cadm_fail scan -d 0x7777 i2csim0/0
i2cadm_fail scan -d 0x10 -d 0x7777 i2csim0/0
i2cadm_fail scan i2csim0/0/0x10
i2cadm_fail scan i2csim0/0/0x70
i2cadm_fail scan i2csim0/0/0x70/0/0x71
i2cadm_fail scan i2csim0/0/0x70/0/0x71/2/0x72

#
# Bad filters
#
i2cadm_fail controller list 2345
i2cadm_fail controller list bl@rgh
i2cadm_fail controller list i2csim7777
i2cadm_fail controller prop get i2csim0 2345
i2cadm_fail controller prop get i2csim0 speed foobar
i2cadm_fail controller prop get i2csimXXyy
i2cadm_fail controller prop get foo^bar
i2cadm_fail device list triforce
i2cadm_fail device list i2csim0 triforce
i2cadm_fail device list i2csim0/XXX
i2cadm_fail device list i2csim0/0/itsatrap
i2cadm_fail device list i2csim0/0/0x11
i2cadm_fail device list magecite%materia
i2cadm_fail device addrs triforce
i2cadm_fail device addrs power courage i2csim0/0
i2cadm_fail device addrs i2csim0/XXX
i2cadm_fail device addrs i2csim0/0/itsatrap
i2cadm_fail device addrs magecite%materia
i2cadm_fail mux list triforce
i2cadm_fail mux list i2csim0 triforce
i2cadm_fail mux list i2csim0/XXX
i2cadm_fail mux list i2csim0/0/itsatrap
i2cadm_fail mux list magecite%materia
i2cadm_fail port list triforce
i2cadm_fail port list power courage i2csim0/0
i2cadm_fail port list i2csim0/XXX
i2cadm_fail port list i2csim0/0/itsatrap
i2cadm_fail port list magecite%materia

#
# Read-only properties
#
i2cadm_fail controller prop set i2csim0 ports=23
i2cadm_fail controller prop set i2csim0 smbus-ops=send-byte
i2cadm_fail controller prop set i2csim0 i2c-max-read=169

#
# Things that should pass. A subset of these we use our simulation based devices
# and verify that the output is as we expect.
#
i2cadm_pass controller list
i2cadm_pass controller list i2csim0
i2cadm_pass controller list smbussim1
i2cadm_pass controller list i2csim0 smbussim1
i2cadm_check_output "i2csim0:i2c" controller list -Hpo name,type i2csim0
i2cadm_check_output "smbussim1" controller list -Hpo name smbussim1
i2cadm_check_output "2:i2csim" controller list -Hpo nports,driver smbussim1
i2cadm_check_output "i2csim0" controller list -Hpo instance i2csim0
i2cadm_check_output "standard:/pseudo/i2csim@0/i2cnex@i2csim0" controller list \
    -Hpo speed,provider i2csim0
i2cadm_pass controller prop get i2csim0
i2cadm_pass controller prop get smbussim1
i2cadm_pass controller prop get i2csim0 speed smbus-ops type
i2cadm_check_output "speed:standard" controller prop get -Hpo property,value \
    i2csim0 speed
i2cadm_check_output "smbus:r-" controller prop get -Hpo value,perm smbussim1 \
    type
i2cadm_check_output "bit32:i2csim0" controller prop get -Hpo type,controller \
    i2csim0 smbus-ops
i2cadm_pass device list
i2cadm_pass device list i2csim0
i2cadm_pass device list i2csim0/0
i2cadm_pass device list ts5111
i2cadm_pass device list pca954x
i2cadm_pass device list at24c4 i2csim0
i2cadm_pass device list i2csim0/0/0x10
i2cadm_pass device list i2csim0/0/0x70/3
i2cadm_check_output "at24c32" device list -Hpo name i2csim0/0/0x10
i2cadm_check_output "at24c08" device list -Hpo name i2csim0/0/0x20
i2cadm_check_output "0x72" device list -Hpo addr i2csim0/0/0x70/0/0x71/0
i2cadm_check_output "0x72" device list -Hpo addr i2csim0/0/0x70/0/0x71/4
i2cadm_check_output "i2csim0/0/0x70/0/0x71/7/0x72" device list -Hpo path \
    i2csim0/0/0x70/0/0x71/7
#
# Claimed addresses come and go so we elide them based on whether the driver is
# attached or detached so we leave them out of the test suite.
#
i2cadm_pass device addrs
i2cadm_pass device addrs i2csim0
i2cadm_pass device addrs pca9548
i2cadm_pass device addrs at24c
i2cadm_pass device addrs i2csim0/0/0x70/1/0x71 ts5111
i2cadm_check_output "7-bit:0x10" device addrs -Hpo type,addr i2csim0/0/0x10
i2cadm_check_output "platform" device addrs -Hpo source i2csim0/0/0x70/2/0x72
i2cadm_pass mux list
i2cadm_pass mux list pca9548
i2cadm_pass mux list pca954x
i2cadm_pass mux list -Ho name,nports,device
i2cadm_pass mux list -po name,nports,device pca954x
i2cadm_pass port list
i2cadm_pass port list i2csim0
i2cadm_pass port list smbussim1
i2cadm_pass port list smbussim1/1
i2cadm_pass port list smbussim1/1 i2csim0/0
i2cadm_pass port list controller
i2cadm_pass port list multiplexor
i2cadm_pass port list i2csim0/0 i2csim0/0/0x70/4
i2cadm_pass port list i2csim0/0/0x70/0/0x71/7
i2cadm_check_output "1:1" port list -Hpo ndevs,tdevs i2csim0/0/0x70/0/0x71/7
i2cadm_check_output "4:4" port list -Hpo name,portno i2csim0/0/0x70/4
i2cadm_check_output "controller" port list -Hpo type smbussim1/1
i2cadm_pass port map i2csim0/0
i2cadm_pass port map i2csim0/0/0x70/3
i2cadm_pass port map i2csim0/0/0x70/0/0x71/7
i2cadm_pass port map smbussim1/1
i2cadm_pass port map -Ho addr,major,driver i2csim0/0
i2cadm_pass port map -po count,type i2csim0/0

if (( i2c_exit == 0 )); then
	printf "All tests passed successfully!\n"
fi

exit $i2c_exit
