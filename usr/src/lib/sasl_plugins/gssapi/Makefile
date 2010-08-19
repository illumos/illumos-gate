#
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
#

include		../Makefile.subdirs

all install: THIRDPARTYLICENSE

THIRDPARTYLICENSE: gssapi.c
	$(SED) -e '/GSSAPI SASL plugin/,/^$$/ p' -e 'd' gssapi.c > $@

CLOBBERFILES += THIRDPARTYLICENSE

include $(SRC)/lib/Makefile.targ
