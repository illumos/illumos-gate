#!/bin/ksh -p
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
# Copyright 2026 Oxide Computer Company
#

. $STF_SUITE/tests/functional/slog/slog.kshlib

#
# DESCRIPTION:
#	Verify that the bytes that pad a TX_WRITE log record's data to a
#	multiple of 8, and the unused attribute fields of a TX_SETATTR
#	record, are written to the log as zeros, not as uninitialized kernel
#	memory.
#
# STRATEGY:
#	1. Create a pool with a slog, and freeze it.
#	2. Write lengths that aren't multiples of 8 to two files: with
#	   O_DSYNC, so the data is copied into the log record when the
#	   write is logged (WR_COPIED), and without, so it's copied into
#	   the log block when the log is committed (WR_NEED_COPY).  Set
#	   the hidden attribute on a file, which logs a TX_SETATTR record
#	   with an xvattr but no create time or scanstamp.
#	3. Unmount to commit the log, read each log block from the slog,
#	   and check the pad bytes after each TX_WRITE record's data, and the
#	   create time and scanstamp of the TX_SETATTR record.
#	4. Export and import the pool to replay the log, and check the files.
#
# A DEBUG kernel fills new kmem buffers (with kmem_flags at its default,
# 0xf), so without the fix these bytes are reliably nonzero.  On a
# non-DEBUG kernel they are whatever the memory held before, usually but
# not always nonzero.
#

verify_runnable "global"

#
# For the log block (ZILOG2: zil_chain_t first) in file $1, print
# "W <foid> <length> <pad bytes> <nonzero pad bytes> <pad in hex>" for each
# TX_WRITE record with data, and "A <foid> <nonzero bytes> <hex>" with the
# create time and scanstamp of each TX_SETATTR record with an xvattr.
#
function log_block_records
{
	od -A n -v -t u1 $1 | nawk '
	function u64(o,		v, i) {
		v = 0
		for (i = 7; i >= 0; i--)
			v = v * 256 + b[o + i]
		return (v)
	}
	function nonzero(from, to,	i) {
		nz = 0
		hex = "-"
		for (i = from; i < to; i++) {
			if (b[i] != 0)
				nz++
			hex = (hex == "-" ? "" : hex) sprintf("%02x", b[i])
		}
	}
	{
		for (i = 1; i <= NF; i++)
			b[n++] = $i
	}
	END {
		# zc_nused follows zc_pad and zc_next_blk; records follow
		# the 184-byte zil_chain_t.
		nused = u64(136)
		for (o = 184; o + 32 <= nused; o += reclen) {
			txtype = u64(o)
			reclen = u64(o + 8)
			if (reclen < 32 || reclen % 8 != 0 || o + reclen > nused)
				break
			# TX_SETATTR; lr_setattr_t is 112 bytes, then an
			# lr_attr_t with a 3-word bitmap (lr_attr_masksize 3),
			# the attributes, the create time (16 bytes) and the
			# scanstamp (32 bytes).
			if (txtype == 11 && reclen >= 184 &&
			    b[o + 112] == 3 && b[o + 113] == 0) {
				nonzero(o + 136, o + 184)
				print "A", u64(o + 32), nz, hex
				continue
			}
			# TX_WRITE; lr_write_t is 192 bytes, lr_length at 48.
			if (txtype != 9 || reclen <= 192)
				continue
			len = u64(o + 48)
			if (192 + len > reclen)
				continue
			nonzero(o + 192 + len, o + reclen)
			print "W", u64(o + 32), len, reclen - 192 - len, nz, hex
		}
	}'
}

log_assert "TX_WRITE and TX_SETATTR log records have no uninitialized bytes."
log_onexit cleanup
log_must setup

log_must zpool create $TESTPOOL $VDEV log mirror $LDEV
log_must zfs create -o compression=off $TESTPOOL/$TESTFS
log_must mkdir -p $TESTDIR

copied=/$TESTPOOL/$TESTFS/copied
needcopy=/$TESTPOOL/$TESTFS/needcopy
lengths="1 2 3 4 5 6 7 9 13 100 1001"
log_must eval "dd if=/dev/urandom of=$TESTDIR/data bs=1001 count=1"
log_must touch $copied $needcopy $TESTDIR/want
for len in $lengths; do
	log_must eval "dd if=$TESTDIR/data of=$TESTDIR/want bs=$len count=1 \
	    seek=1 conv=notrunc"
done

# Make sure the dataset has a ZIL header before freezing.
log_must dd if=/dev/zero of=/$TESTPOOL/$TESTFS/sync oflag=dsync,sync \
    bs=1 count=1
log_must zpool freeze $TESTPOOL
for len in $lengths; do
	log_must eval "dd if=$TESTDIR/data of=$copied bs=$len count=1 \
	    seek=1 conv=notrunc oflag=dsync"
	log_must eval "dd if=$TESTDIR/data of=$needcopy bs=$len count=1 \
	    seek=1 conv=notrunc"
done
log_must chmod S+vhidden $needcopy
cfoid=$(ls -i $copied | nawk '{print $1}')
nfoid=$(ls -i $needcopy | nawk '{print $1}')
log_must zfs unmount $TESTPOOL/$TESTFS

zdbout=$TESTDIR/zdb.out
log_must eval "zdb -ivvvvv $TESTPOOL/$TESTFS >$zdbout"
grep "Block seqno" $zdbout | grep -vq zilog2 && \
    log_fail "log block checksum isn't zilog2"
dev=${LDEV%% *}
recs=$TESTDIR/records
rm -f $recs
for dva in $(sed -n 's/.*Block seqno.*DVA\[0\]=<\([0-9a-f:]*\)>.*/\1/p' \
    $zdbout); do
	# A DVA is vdev:offset:asize, in hex.  The offset is from the end of
	# the 4M of labels and boot block at the start of the device.
	dva=${dva#*:}
	off=$(( (16#${dva%%:*} + 4 * 1024 * 1024) / 512 ))
	size=$(( 16#${dva#*:} / 512 ))
	log_must eval "dd if=$dev of=$TESTDIR/blk bs=512 skip=$off \
	    count=$size 2>/dev/null"
	log_block_records $TESTDIR/blk >>$recs
done
log_note "log records (W foid length pad nonzero hex; A foid nonzero hex):" \
    "\n$(cat $recs)"

typeset -i bad=0
for foid in $cfoid $nfoid; do
	for len in $lengths; do
		pad=$(( (8 - len % 8) % 8 ))
		nawk -v f=$foid -v l=$len -v p=$pad \
		    '$1 == "W" && $2 == f && $3 == l && $4 == p {found = 1}
		    END {exit (!found)}' $recs || \
		    log_fail "no record of $len bytes for object $foid"
	done
	n=$(nawk -v f=$foid '$1 == "W" && $2 == f && $5 != 0' $recs | wc -l)
	log_note "object $foid: $n records with nonzero pad bytes"
	(( bad += n ))
done
(( bad == 0 )) || log_fail "$bad TX_WRITE records have nonzero pad bytes"

nawk -v f=$nfoid '$1 == "A" && $2 == f {found = 1} END {exit (!found)}' \
    $recs || log_fail "no TX_SETATTR record with an xvattr for object $nfoid"
nawk -v f=$nfoid '$1 == "A" && $2 == f && $3 != 0 {bad = 1}
    END {exit (bad)}' $recs || \
    log_fail "TX_SETATTR record has a nonzero create time or scanstamp"

log_must zpool export $TESTPOOL
log_must zpool import -f -d $VDIR $TESTPOOL
log_must cmp $TESTDIR/want $copied
log_must cmp $TESTDIR/want $needcopy

log_pass "TX_WRITE and TX_SETATTR log records have no uninitialized bytes."
