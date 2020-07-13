#!/usr/bin/ksh
#
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
# Copyright 2020 Oxide Computer Company
#

#
# This is a stress test that tries to just generate a bunch of ksensor
# activity. It will run launching a number of threads that do different
# activities. The goal here is to try and have the following:
#
# o Things trying to modunload the ksensor_test and ksensor driver
# o things trying to actually use the various sensors from the
#   ksensor_test driver
#
# To make sure that everything cleans up when this exits, this script
# wraps itself in a ctrun. The caller needs to ensure that the
# ksensor_test driver is loaded to begin with. It may or may not be part
# of the system when all is said and done.
#

sensor_base="/dev/sensors/test"

#
# The number of instances that we expect to exist.
#
sensor_inst=42
sensor_count=4

#
# Tunnables
#
sensor_unloaders=50
sensor_readers=500

if [[ ${@:$#} != "elbereth" ]]; then
	exec ctrun -o noorphan ksh $0 "elbereth"
fi


if [[ ! -L "$sensor_base/test.temp.0.1" ]]; then
	printf "missing ksensor test data, ksensor_temp driver loaded\n" 2>&1
	exit 1
fi

cat << EOL
Beginning to run the ksensor stress test. This will launch processes
which will:

 o Attempt to modunload 'ksensor' driver ($sensor_unloaders procs)
 o Attempt to modunload 'ksensor_test' driver ($sensor_unloaders procs)
 o Attempt to read test sensors ($sensor_readers procs)

To stop things, simply kill this process. All dependent processes will
be cleaned up.
EOL

for ((i = 0; i < $sensor_unloaders; i++)); do
	ksh ./ksensor_unload.ksh ksensor_test &
	ksh ./ksensor_unload.ksh ksensor &
done

for ((i = 0; i < $sensor_readers; i++)); do
	if [[ $(( $i % 2 )) -eq 0 ]]; then
		./ksensor_sread.32 $sensor_inst $sensor_count &
	else
		./ksensor_sread.64 $sensor_inst $sensor_count &
	fi
done

while :; do
	wait
done

exit 0
