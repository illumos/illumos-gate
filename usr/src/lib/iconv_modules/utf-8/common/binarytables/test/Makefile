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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#


CODESETS = IBM-037 IBM-273 IBM-277 IBM-278 IBM-280 IBM-284 IBM-285 IBM-297 \
IBM-420 IBM-424 IBM-500 \
IBM-850 IBM-852 IBM-855 IBM-856 IBM-857 IBM-862 IBM-864 IBM-866 IBM-869 \
IBM-870 IBM-875 IBM-880 \
IBM-921 IBM-922 IBM-1025 IBM-1026 IBM-1046 IBM-1112 \
CP850 CP852 CP855 CP857 CP862 CP864 CP869 CP866\
CP874 \
CP1250 CP1251 CP1252 CP1253 CP1254 CP1255 CP1256 CP1257 CP1258 IBM-1122


OUT1 = $(CODESETS:%=%.out1)
OUT2 = $(CODESETS:%=%.out2)
MNMC = $(CODESETS:%=%.mnmc)

OUTE = UTF-EBCDIC.out2

MNCSPRS = IBM-273.mnmc IBM-277.mnmc IBM-278.mnmc IBM-280.mnmc IBM-284.mnmc \
IBM-285.mnmc IBM-297.mnmc  IBM-420.mnmc IBM-424.mnmc \
IBM-850.mnmc IBM-852.mnmc IBM-855.mnmc IBM-857.mnmc IBM-862.mnmc IBM-864.mnmc \
IBM-870.mnmc IBM-880.mnmc \
IBM-1026.mnmc

CFLAGS	+=	-g

SB_TO_UTF8_TEST = sb_to_utf8_test
UTF8_TO_EBCDIC_TEST = utf8_to_ebcdic_test
MKMNMCSTBL = mkmnmcstbl

OBJECTS = $(SB_TO_UTF8_TEST) $(UTF8_TO_EBCDIC_TEST) $(MKMNMCSTBL)

test: $(OBJECTS) $(OUT1) $(OUT2) $(OUTE)

mn: $(MNMC)


clean:
	-rm  $(OUT1) $(OUT2) $(OUTE)
clobber: clean
	-rm $(OBJECTS)


test1: $(OUT1)
test2: $(OUT2)

ebcdic: $(OUTE)


UTF%.out2: UTF%
	$(UTF8_TO_EBCDIC_TEST)  $< > $@


.SUFFIXES: $(SUFFIXES) .out
.PRECIOUS: %.out

%.out1: %
	$(SB_TO_UTF8_TEST) -c ../util $< > $@
#	$(SB_TO_UTF8_TEST) $< > $@

%.out2: %
	$(UTF8_TO_EBCDIC_TEST) $< > $@

%.mnmc: %.txt
	 $(MKMNMCSTBL) mnemonics.txt < ../util/$< > $@

UTF-EBCDIC.out2: UTF-EBCDIC
	$(UTF8_TO_EBCDIC_TEST) UTF-EBCDIC > $@
#	$(UTF8_TO_EBCDIC_TEST) -b -d UTF-EBCDIC > $@.big




%_test:%_test.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)
%tbl:%tbl.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

mnpr:
	pr $(MNCSPRS) | lp

%: FRC


FRC:

#
$(OUT1): $(SB_TO_UTF8_TEST)
$(OUT2) $(OUTE) :$(UTF8_TO_EBCDIC_TEST)
$(MNMC): $(MKMNMCSTBL)
