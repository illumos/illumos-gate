#!/bin/sh
#
# hal-system-system-power-suspend-sunos.sh
#
# Licensed under the Academic Free License version 2.1
#

alarm_not_supported() {
	echo org.freedesktop.Hal.Device.SystemPowerManagement.AlarmNotSupported >&2
	echo Waking the system up is not supported >&2
	exit 1
}

unsupported() {
	echo org.freedesktop.Hal.Device.SystemPowerManagement.NotSupported >&2
	echo No suspend method found >&2
	exit 1
}

read seconds_to_sleep
if [ $seconds_to_sleep != "0" ] ; then
	alarm_not_supported
fi

if [ -x "/usr/sbin/uadmin" ] ; then
	/usr/sbin/uadmin 3 20 
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
