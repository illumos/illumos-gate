#!/bin/sh

# Copyright (c) 1999 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"

UNAME_R=`/usr/bin/uname -r`

OS_MAJOR=`echo $UNAME_R | /usr/bin/sed -e 's/^\([^.]*\).*/\1/'`
OS_MINOR=`echo $UNAME_R | /usr/bin/sed -e 's/^[^.]*\.\([^.]*\).*/\1/'`
OS_VERSION=`echo $UNAME_R | tr '.' '_'`

cat <<EOF > new_os_version.h
#ifndef OS_VERSION_H
#define OS_VERSION_H

#define SUNOS_$OS_VERSION
#define OS_MAJOR $OS_MAJOR
#define OS_MINOR $OS_MINOR

#endif
EOF

if [ -f os_version.h ]; then
	if /usr/bin/cmp -s new_os_version.h os_version.h; then
		/usr/bin/rm -f new_os_version.h
	else
		/usr/bin/rm -f os_version.h
		/usr/bin/mv new_os_version.h os_version.h
	fi
else
	/usr/bin/mv new_os_version.h os_version.h
fi
