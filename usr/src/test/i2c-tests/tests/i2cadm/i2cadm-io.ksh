#! /usr/bin/ksh
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
# Copyright 2025 Oxide Computer Company
#

#
# Perform various I/O tests against our virtual devices. Several of the at24c
# devices have content pre-loaded into them with parts of Tolkienian rhymes. We
# can only perform SMBus operations against the at24c08 as the others require a
# two byte I/O pattern.
#

. $(dirname $0)/common.ksh

#
# Variable where the results of performing I/O will be sent.
#
io_data=
io_eedev=
io_dd=

function i2c_at24c_to_eedev
{
	typeset path="$1"
	typeset drv="$2"
	typeset part=

	part=$(i2cadm device list -Hpo instance $path | sed "s/$drv/$drv\//")
	[[ -z "$part" ]] && fatal "failed to translate $path"
	io_eedev="/dev/eeprom/$part/eeprom"
}

function do_io
{
	io_data=$($I2CADM io -o /dev/stdout $@)
	if (( $? != 0 )); then
		fatal "failed to perform I/O $@"
	fi
}

function check_io
{
	typeset desc="$1"
	typeset targ="$2"
	shift
	shift

	do_io $@
	if [[ "$targ" != "$io_data" ]]; then
		warn "$desc: I/O mismatch: found [$io_data], expected [$targ]"
	else
		printf "TEST PASSED: %s\n" "$desc"
	fi
}

function get_dd
{
	typeset off="$1"
	typeset len="$2"

	[[ -z "$io_eedev" ]] && fatal "missing required eedev path"

	io_dd=$(dd iseek=$off bs=1 count="$len" if=$io_eedev of=/dev/stdout \
	    status=none)
	if (( $? != 0 )); then
		fatal "failed to dd on $io_eedev"
	fi
}

function compare_io_dd
{
	typeset desc="$1"

	if [[ "$io_dd" != "$io_data" ]]; then
		warn "$desc: dd and i2c disagree, found $io_dd (dd) and " \
		"$io_data (i2c)"
	else
		printf "TEST PASSED: %s\n" "$desc"
	fi
}

function write_io
{
	typeset desc="$1"
	typeset targ="$2"
	typeset len="$3"
	typeset off="$4"
	typeset dev="$5"
	shift
	shift
	shift
	shift
	shift

	#
	# Bump len by one to write the offset
	#
	if ! $I2CADM io -d "$dev" $@; then
		fatal "failed to perform I/O $@"
	fi

	check_io "$desc" "$targ" -d $dev -w 1 -r $len $off
}

#
# First Verify that basic I/O makes sense.
#
check_io "Three Rings i2c" "Three rings" -d i2csim0/0/0x20 -r 11 -w 1 0x00
check_io "Three Rings offset i2c" "rings" -d i2csim0/0/0x20 -r 5 -w 1 0x06
check_io "Three Rings recv-u8 (1)" " " -d i2csim0/0/0x20 -m recv-u8
check_io "Three Rings recv-u8 (2)" "f" -d i2csim0/0/0x20 -m recv-u8
check_io "Three Rings read-u8 (1)" "E" -d i2csim0/0/0x20 -m read-u8 -c 0x10
check_io "Three Rings read-u8 (2)" "-" -d i2csim0/0/0x20 -m read-u8 -c 0x15
check_io "Three Rings read-u16" "El" -d i2csim0/0/0x20 -m read-u16 -c 0x10
check_io "Three Rings read-u32" "king" -d i2csim0/0/0x20 -m read-u32 -c 0x16
check_io "Three Rings read-u64" "the sky," -d i2csim0/0/0x20 -m read-u64 -c 0x23
check_io "Three Rings read-block-i2c" "Elven-kings, und" -d i2csim0/0/0x20 \
    -m read-block-i2c -c 0x10 -r 0x10
check_io "Three Rings i2c (all)" "Three rings for Elven-kings, under the sky," \
    -d i2csim0/0/0x20 -r 0x2b -w 1 0x00
check_io "Three Rings block (all)" "Three rings for Elven-kings, under the sky," \
    -d i2csim0/0/0x20 -m read-block-i2c -c 0x00 -r 0x2b

#
# Next, we want to verify that using /dev/eeprom and the io mechanism is
# similar. First we'll verify reads across all the different segments of the
# at24c08.
#
i2c_at24c_to_eedev i2csim0/0/0x20 at24c
get_dd 0 43
compare_io_dd "at24cs08 block 0 comparison"

check_io "Seven i2c (all)" "Seven for the Dwarf-lords in their halls of stone," \
    -d i2csim0/0 -a 0x21 -r 0x32 -w 1 0x00
get_dd 256 50
compare_io_dd "at24cs08 block 1 comparison"

check_io "Nine i2c (all)" "Nine for Moral Men, doomed to die," \
    -d i2csim0/0 -a 0x22 -r 0x22 -w 1 0x00
get_dd 512 34
compare_io_dd "at24cs08 block 2 comparison"

check_io "One i2c (all)" "One for the dark Lord on his dark throne" \
    -d i2csim0/0 -a 0x23 -r 0x28 -w 1 0x00
get_dd 768 40
compare_io_dd "at24cs08 block 3 comparison"

#
# Now it's time to do our write testing. One caveat with the at24c08 is that
# writes that are larger than a 16-byte segment will wrap and start over at the
# beginning. This means that we'll need to be a bit more mindful of our offsets.
# We start an offset of 128 (0x80) to avoid our existing data.
#
write_io "i2c write" "All that is gold" 16 0x80 i2csim0/0/0x20 -w 17 0x80 0x41 \
    0x6c 0x6c 0x20 0x74 0x68 0x61 0x74 0x20 0x69 0x73 0x20 0x67 0x6f 0x6c 0x64
get_dd 128 16
compare_io_dd "All that is gold i2c write"
write_io "write-u8" " " 1 0x90 i2csim0/0/0x20 -m write-u8 -c 0x90 0x20
write_io "write-u16" "do" 2 0x91 i2csim0/0/0x20 -m write-u16 -c 0x91 0x6f64
write_io "write-u8" "e" 1 0x93 i2csim0/0/0x20 -m write-u8 -c 0x93 0x65
write_io "write-u32" "s no" 4 0x94 i2csim0/0/0x20 -m write-u32 -c 0x94 \
    0x6f6e2073
write_io "write-u64" "t glitte" 8 0x98 i2csim0/0/0x20 -m write-u64 -c 0x98 \
    0x657474696c672074
check_io "write stanza 2 (block)" " does not glitte" -d i2csim0/0/0x20 \
    -m read-block-i2c -c 0x90 -r 0x10
get_dd 144 16
compare_io_dd "does not glitter i2c write"

#
# Do a 16 byte block write over the existing portion and show that it
# overwrites. Do this manually as the general I/O check logic is going to have
# trouble with this. This takes the string 'r, Not all those' and offsets it 4
# bytes.
#
if ! $I2CADM io -d i2csim0/0/0x20 -m write-block-i2c -c 0x94 -w 16 \
    0x72 0x2c 0x20 0x4e 0x6f 0x74 0x20 0x61 0x6c 0x6c 0x20 0x74 0x68 0x6f 0x73 \
    0x65; then
	fatal "failed to perform i2c block write"
fi
check_io "write stanza 3 (block)" "hoser, Not all t" -d i2csim0/0/0x20 \
    -m read-block-i2c -c 0x90 -r 0x10
get_dd 144 16
compare_io_dd "i2c block overwrite"

if (( i2c_exit == 0 )); then
	printf "All tests passed successfully!\n"
fi

exit $i2c_exit
