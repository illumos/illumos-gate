#
# hal-fdi-validate.sh : Validate one or more fdi(4) files
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Licensed under the Academic Free License version 2.1
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

usage() {
	echo "Usage: hal-fdi-validate [-f dtd] file [file ...]"
	exit 1
}

if [ "$1" = "-f" ]; then
	if [ "foo$2" != "foo" ] ; then
		DTD="$2"
		shift 2
	else
		usage
	fi
else
	DTD="/usr/share/lib/xml/dtd/fdi.dtd.1"
fi

if [ $# -eq 0 ]; then
	usage
fi

xmllint --noout --dtdvalid $DTD $*
