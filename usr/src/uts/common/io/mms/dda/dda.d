/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#!/usr/sbin/dtrace -qs

/*
 * dda dtrace probes 
 *
 * sort -k 1 on timestamps to order dtrace output.
 */

BEGIN
{
	printf("%-16s %-20s %-20s %4s %s\n",
	    "TIMESTAMP", "FUNCTION", "PROBE", "INST", "DATA");
}

/*
 * uncomment entry and return to get complete function call path.
 */

/*
:dda::entry
{
	printf("%016lu %-20s %-20s\n", timestamp, probefunc, probename);
}

:dda::return
{
	printf("%016lu %-20s %-20s\n", timestamp, probefunc, probename);
}
*/

:dda::dda_pid
{
	printf("%016lu %-20s %-20s %4d pid %d\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_loaded_already
{
	printf("%016lu %-20s %-20s %4d %s\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1));
}

:dda::dda_cmd_load_resume
{
	printf("%016lu %-20s %-20s %4d %s\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1));
}

:dda::dda_cmd_load_err
{
	printf("%016lu %-20s %-20s %4d %s error %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2);
}

:dda::dda_cmd_load
{
	printf("%016lu %-20s %-20s %4d %s\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1));
}

:dda::dda_cmd_unload
{
	printf("%016lu %-20s %-20s %4d %s\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1));
}

:dda::dda_cmd_unload_err
{
	printf("%016lu %-20s %-20s %4d %s error %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2);
}

:dda::dda_capacity
{
	printf("%016lu %-20s %-20s %4d capacity %ld space %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_cmd_erase
{
	printf("%016lu %-20s %-20s %4d lba %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_erase_err
{
	printf("%016lu %-20s %-20s %4d error %d\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_wfm
{
	printf("%016lu %-20s %-20s %4d lba %ld count %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_cmd_wfm_eom
{
	printf("%016lu %-20s %-20s %4d lba %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_write
{
	printf("%016lu %-20s %-20s %4d lba %ld length %d blocks %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_write_ew
{
	printf("%016lu %-20s %-20s %4d alt write flag %d\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_write_eom
{
	printf("%016lu %-20s %-20s %4d lba %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_write_vn_err
{
	printf("%016lu %-20s %-20s %4d lba %ld offset %ld error %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_write_ew
{
	printf("%016lu %-20s %-20s %4d lba %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_write_done
{
	printf("%016lu %-20s %-20s %4d lba %ld blocks %d resid %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_write_err
{
	printf("%016lu %-20s %-20s %4d lba %ld err %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_cmd_read
{
	printf("%016lu %-20s %-20s %4d lba %ld length %d blocks %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_read_ffpns
{
	printf("%016lu %-20s %-20s %4d fm forward pending no skip\n",
	    timestamp, probefunc, probename, arg0);
}

:dda::dda_cmd_read_ffpc
{
	printf("%016lu %-20s %-20s %4d fm forward pending cleared\n",
	    timestamp, probefunc, probename, arg0);
}

:dda::dda_cmd_read_eot
{
	printf("%016lu %-20s %-20s %4d lba %ld eot eio %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_cmd_read_blksz
{
	printf("%016lu %-20s %-20s %4d blksize %d blkcount %d overflow %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_read_noblks
{
	printf("%016lu %-20s %-20s %4d\n",
	    timestamp, probefunc, probename, arg0);
}

:dda::dda_cmd_read_numblks
{
	printf("%016lu %-20s %-20s %4d len %d blksize %d blkcount %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_read_short
{
	printf("%016lu %-20s %-20s %4d lba %ld resid %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_cmd_read_overflow
{
	printf("%016lu %-20s %-20s %4d lba %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_read_fm
{
	printf("%016lu %-20s %-20s %4d lba %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_read_vn_err
{
	printf("%016lu %-20s %-20s %4d lba %ld offset %ld error %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_read_resid
{
	printf("%016lu %-20s %-20s %4d resid %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_bsearch
{
	printf("%016lu %-20s %-20s %4d key %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_locate
{
	printf("%016lu %-20s %-20s %4d lba %ld position %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_cmd_locate_err
{
	printf("%016lu %-20s %-20s %4d error %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_locate_done
{
	printf("%016lu %-20s %-20s %4d at lba %ld fileno %ld blkno %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_grsz
{
	printf("%016lu %-20s %-20s %4d get record size %d ili %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_cmd_srsz
{
	printf("%016lu %-20s %-20s %4d set record size %d ili %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_cmd_status
{
	printf("%016lu %-20s %-20s %4d status %d resid %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_cmd_ili
{
	printf("%016lu %-20s %-20s %4d set ili %d\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_fsr
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld count %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_fsr_fm
{
	printf("%016lu %-20s %-20s %4d hit fm\n",
	    timestamp, probefunc, probename, arg0);
}

:dda::dda_cmd_fsr_done
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld resid %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_fsr_err
{
	printf("%016lu %-20s %-20s %4d error %d\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_fsr_where
{
	printf("%016lu %-20s %-20s %4d pos %ld blkcount %ld fmcount %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_fsr_blks
{
	printf("%016lu %-20s %-20s %4d blks %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_bsr
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld count %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_bsr_fm
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld hit fm\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_cmd_bsr_done
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld resid %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_bsr_err
{
	printf("%016lu %-20s %-20s %4d error %d\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_bsr_where
{
	printf("%016lu %-20s %-20s %4d pos %ld blkcount %ld fmcount %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_bsr_blks
{
	printf("%016lu %-20s %-20s %4d blks %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_fsf
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld count %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_fsf_pend
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld count %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_fsf_err
{
	printf("%016lu %-20s %-20s %4d error %d\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_fsf_done
{
	printf("%016lu %-20s %-20s %4d at lba %ld fileno %ld resid %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_bsf
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld count %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_bsf_err
{
	printf("%016lu %-20s %-20s %4d error %d\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_bsf_done
{
	printf("%016lu %-20s %-20s %4d at lba %ld fileno %ld resid %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_eom
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld blkno %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_cmd_eom_err
{
	printf("%016lu %-20s %-20s %4d error %d\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_cmd_nop
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_cmd_rewind_err
{
	printf("%016lu %-20s %-20s %4d error %d\n",
	    timestamp, probefunc, probename, arg0, arg1);
}


:dda::dda_cmd_rewind
{
	printf("%016lu %-20s %-20s %4d lba %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_write_index
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld offset %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_read_index
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld offset %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_gen_next_index
{
	printf("%016lu %-20s %-20s %4d lba %ld fileno %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg3);
}

:dda::dda_stripe_align_enter
{
	printf("%016lu %-20s %-20s %4d\n",
	    timestamp, probefunc, probename, arg0);
}

:dda::dda_stripe_align_amount
{
	printf("%016lu %-20s %-20s %4d stripe %d amount %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_stripe_align
{
	printf("%016lu %-20s %-20s %4d stripe %d amount %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_data_offset_start
{
	printf("%016lu %-20s %-20s %4d offset %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_data_offset_le
{
	printf("%016lu %-20s %-20s %4d offset %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_data_offset_gt
{
	printf("%016lu %-20s %-20s %4d offset %ld\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_data_offset_align
{
	printf("%016lu %-20s %-20s %4d offset %ld amount %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_data_offset
{
	printf("%016lu %-20s %-20s %4d lba %ld offset %ld\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_sec_align_vn_null
{
	printf("%016lu %-20s %-20s %4d error, null data file\n",
	    timestamp, probefunc, probename, arg0);
}

:dda::dda_sec_align_err
{
	printf("%016lu %-20s %-20s %4d metadata update error %d\n",
	    timestamp, probefunc, probename, arg0, arg1);
}

:dda::dda_sec_align
{
	printf("%016lu %-20s %-20s %4d sector alignment old %d new %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2);
}

:dda::dda_ew_eom
{
	printf("%016lu %-20s %-20s %4d count %d avail %d ew %d\n",
	    timestamp, probefunc, probename, arg0, arg1, arg2, arg3);
}

:dda::dda_vn_open_err
{
	printf("%016lu %-20s %-20s %4d file %s error %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2);
}

:dda::dda_vn_open_access
{
	printf("%016lu %-20s %-20s %4d file %s error %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2);
}

:dda::dda_vn_*_null
{
	printf("%016lu %-20s %-20s %4d null vnode pointer\n",
	    timestamp, probefunc, probename, arg0);
}

:dda::dda_vn_lock_sysid
{
	printf("%016lu %-20s %-20s %4d file %s cmd %x\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2);
}

:dda::dda_vn_lock_err
{
	printf("%016lu %-20s %-20s %4d file %s cmd %x error %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2, arg3);
}

:dda::dda_vn_close_err
{
	printf("%016lu %-20s %-20s %4d file %s error %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2);
}

:dda::dda_vn_read_err
{
	printf("%016lu %-20s %-20s %4d file %s offset %ld error %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2, arg3);
}

:dda::dda_vn_*_resid
{
	printf("%016lu %-20s %-20s %4d file %s offset %ld resid %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2, arg3);
}

:dda::dda_vn_write_err
{
	printf("%016lu %-20s %-20s %4d file %s offset %ld error %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2, arg3);
}

:dda::dda_vn_truncate_err
{
	printf("%016lu %-20s %-20s %4d file %s offset %ld error %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2, arg3);
}

:dda::dda_vn_sync_err
{
	printf("%016lu %-20s %-20s %4d file %s error %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2);
}

:dda::dda_vn_size_err
{
	printf("%016lu %-20s %-20s %4d file %s error %d\n",
	    timestamp, probefunc, probename, arg0, stringof(arg1), arg2);
}
