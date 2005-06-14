#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

LIBRARY= gssapi.a
VERS= .1

PLUG_OBJS=	gssapi.o	gssapiv2_init.o

PLUG_LIBS =	-lgss

# include common definitions
include ../../Makefile.com
