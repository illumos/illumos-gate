#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

LIBRARY= plain.a
VERS= .1

PLUG_OBJS=	plain.o		plain_init.o

# include common definitions
include ../../Makefile.com
