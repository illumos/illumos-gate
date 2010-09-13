#!/bin/sh
#
# hal-system-power-hibernate-sunos.sh
#
# Licensed under the Academic Free License version 2.1
#

unsupported() {
	echo org.freedesktop.Hal.Device.SystemPowerManagement.NotSupported >&2
	echo No hibernate method found >&2
	exit 1
}

if [ -x "/usr/sbin/uadmin" ] ; then
	/usr/sbin/uadmin 3 0 
	RET=$?
else
	unsupported
fi

#Refresh devices as a resume can do funny things
for type in button battery ac_adapter
do
	devices=`hal-find-by-capability --capability $type`
	for device in $devices
	do
		dbus-send --system --print-reply --dest=org.freedesktop.Hal \
			  $device org.freedesktop.Hal.Device.Rescan
	done
done

exit $RET
