#! /usr/bin/sh
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
# Copyright 2017 Nexenta Systems, Inc.
#

# Combine LC_CTYPE classes from all .UTF-8.src files to be compiled by localedef
# into one LC_CTYPE/LCL_DATA used by all locales, so we have the same case
# mapping tables, character classes, etc. for all of them. This is not general
# purpose parser but is good enough for the stock files supplied with CLDR.

printf "\nLC_CTYPE\n"

for i in upper lower alpha space cntrl graph print punct digit xdigit blank \
	toupper tolower; do
	# sed can't match both range patterns on the same line so we just make
	# it look like valid multiline class by duplicating the definition
	sed "/^$i.*>$/ {
		s,$,;/,
		h
		s,^$i\(.*>\);/$,\1,
		H
		x
	}" $@ |\
	sed -n "/^$i/,/\([>)]\)$/ {
		s,^$i,,
		"'s,\([>)]\)$,\1;/,'"
		/^$/d
		p
	}" |\
	sort -u |\
	sed "1 s,^,$i,;$ s,\([>)]\);/,\1,"
done

# Add the manually assembled definitions from FreeBSD
# (originally tools/tools/locale/etc/manual-input.UTF-8).
cat data/manual-input.UTF-8

printf "\nEND LC_CTYPE\n"
