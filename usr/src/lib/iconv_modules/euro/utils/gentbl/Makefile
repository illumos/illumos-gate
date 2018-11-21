#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

# Toolset to unify the code conversion tables.
# Created for one-time use.

include $(SRC)/Makefile.master

INTEGRATED = \
	646%8859.c \
	646da%8859.c \
	646de%8859.c \
	646en%8859.c \
	646es%8859.c \
	646fr%8859.c \
	646it%8859.c \
	646sv%8859.c \
	8859%646.c \
	8859%646da.c \
	8859%646de.c \
	8859%646en.c \
	8859%646es.c \
	8859%646fr.c \
	8859%646it.c \
	8859%646sv.c \
	8859-1%IBM-037.c \
	8859-1%IBM-500.c \
	8859-1%IBM-850.c \
	IBM-037%8859-1.c \
	IBM-500%8859-1.c \
	IBM-850%8859-1.c \
	alt%iso5.c \
	alt%koi8.c \
	alt%mac.c \
	alt%win5.c \
	dhn%dos2.c \
	dhn%iso2.c \
	dhn%maz.c \
	dhn%win2.c \
	dos2%dhn.c \
	dos2%iso2.c \
	dos2%maz.c \
	dos2%win2.c \
	iso2%dhn.c \
	iso2%dos2.c \
	iso2%maz.c \
	iso2%win2.c \
	iso5%alt.c \
	iso5%koi8.c \
	iso5%mac.c \
	iso5%win5.c \
	koi8%alt.c \
	koi8%iso5.c \
	koi8%mac.c \
	koi8%win5.c \
	mac%alt.c \
	mac%iso5.c \
	mac%koi8.c \
	mac%win5.c \
	maz%dhn.c \
	maz%dos2.c \
	maz%iso2.c \
	maz%win2.c \
	win2%dhn.c \
	win2%dos2.c \
	win2%iso2.c \
	win2%maz.c \
	win5%alt.c \
	win5%iso5.c \
	win5%koi8.c \
	win5%mac.c

MISSING = \
	alt%iso.c \
	alt%koi.c \
	alt%win.c \
	dhn%ib2.c \
	dhn%is2.c \
	dhn%wi2.c \
	ib2%dhn.c \
	ib2%is2.c \
	ib2%maz.c \
	ib2%wi2.c \
	is2%dhn.c \
	is2%ib2.c \
	is2%maz.c \
	is2%wi2.c \
	iso%alt.c \
	iso%koi.c \
	iso%mac.c \
	iso%win.c \
	koi%alt.c \
	koi%iso.c \
	koi%mac.c \
	koi%win.c \
	mac%iso.c \
	mac%koi.c \
	mac%win.c \
	maz%ib2.c \
	maz%is2.c \
	maz%wi2.c \
	wi2%dhn.c \
	wi2%ib2.c \
	wi2%is2.c \
	wi2%maz.c \
	win%alt.c \
	win%iso.c \
	win%koi.c \
	win%mac.c

MODULES	= $(INTEGRATED)
# $(MISSING)

BINARYTABLES = \
        8859-16%8859-2 \
        8859-16%ibm850 \
        8859-16%ibm870 \
        8859-2%8859-16 \
        ibm850%8859-16 \
        ibm870%8859-16

TABLES = table.8859-1.IBM-500.c table.IBM-500.8859-1.c table.alt.iso.c table.alt.koi.c \
table.alt.mac.c table.alt.win.c table.dhn.ib2.c table.dhn.is2.c table.dhn.maz.c table.dhn.wi2.c table.ib2.dhn.c table.ib2.is2.c \
table.ib2.maz.c table.ib2.wi2.c table.is2.dhn.c table.is2.ib2.c table.is2.maz.c table.is2.wi2.c table.iso.alt.c table.iso.koi.c \
table.iso.mac.c table.iso.win.c table.koi.alt.c table.koi.iso.c table.koi.mac.c table.koi.win.c table.mac.alt.c table.mac.iso.c \
table.mac.koi.c table.mac.win.c table.maz.dhn.c table.maz.ib2.c table.maz.is2.c table.maz.wi2.c table.wi2.dhn.c table.wi2.ib2.c \
table.wi2.is2.c table.wi2.maz.c table.win.alt.c table.win.iso.c table.win.koi.c table.win.mac.c

GEN_SRC = $(MODULES:%.c=gen_%.c)
GEN_BIN = $(MODULES:%.c=gen_%)
TBL = $(MODULES:%.c=%.tbl)
HEADERS = $(MODULES:%.c=%.head)
BTBL = $(BINARYTABLES:%=%.btbl)

all: $(TBL) $(BTBL)
	echo Now run: ./rename

# .c -> .tbl
gen_%.c: ../%.c debug.inc
	cat $< debug.inc > $@

%.head: ../%.c
	awk '/stdio.h/{x=1} x==0 && !/^#ident/ && $$1!="" {print}' $< > $@

gen_%: gen_%.c
	$(CC) -xO3 -I. -I.. -DDEBUG -o $@ $<

%.tbl: gen_% %.head input copyright
	./$< input > $@.tmp
	ID=`echo $@ | perl -pe 's:\.tbl::'` ; \
	echo "\n/*\n * Automatically generated from: $$ID.c\n */" > $$ID.info ; \
	cat $$ID.head $$ID.info copyright $@.tmp > $@
	$(RM) $@.tmp

debug.inc:
	printf "\n#include \"debug.c\"\n\n" > $@

geninput: geninput.c
	$(CC) -o $@ geninput.c

input: geninput
	./geninput > $@

gentbl: gentbl.c
	$(CC) -o $@ gentbl.c


# .bt -> .btbl
%.btbl: %.out btbl.head
	./rewritetbl $< > $@.tmp
	ID=`echo $@ | perl -pe 's:\.btbl::'` ; \
	echo "\n/*\n * Automatically generated from: $$ID.bt\n */" > $$ID.info ; \
	cat btbl.head $$ID.info $@.tmp > $@
	$(RM) $@.tmp

%.out: input
	FROM=`echo $@ | perl -pe 's:%.*::'` ; \
	TO=`echo $@ | perl -pe 's:.*%:: ; s:\.out::'` ; \
	/usr/bin/iconv -f $$FROM -t $$TO input > $@

btbl.head: rewritetbl.c
	awk '/stdio.h/{x=1} x==0 && $$1!="" {print}' rewritetbl.c  > $@

rewritetbl: rewritetbl.c
	$(CC) -o $@ rewritetbl.c

clean:
	$(RM) -r *.head *.tbl gen_* *info debug.inc *.out *.btbl
