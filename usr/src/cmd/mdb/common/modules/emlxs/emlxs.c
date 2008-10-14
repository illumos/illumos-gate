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
 */

/*
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */

#include "emlxs_mdb.h"
#include "emlxs_msg.h"
#include "emlxs_device.h"

/*
 * MDB module linkage information:
 */

static const mdb_dcmd_t dcmds[] =
{
	{ "emlxs_msgbuf", "<instance>",
	"dumps the emlxs driver internal message buffer",
	emlxs_msgbuf, emlxs_msgbuf_help},
	{ NULL }
};

static const mdb_modinfo_t modinfo =
{
	MDB_API_VERSION,
	dcmds,
	NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}


/*
 * emlxs_msgbuf library
 */
void
emlxs_msgbuf_help()
{

	mdb_printf("Usage:   ::%s_msgbuf <instance (in hex)>\n\n", DRIVER_NAME);
	mdb_printf(
	"         <instance>  This is the %s driver instance number in hex.\n",
	    DRIVER_NAME);
	mdb_printf("                      (e.g. 0, 1,..., e, f, etc.)\n");

} /* emlxs_msgbuf_help() */


/*ARGSUSED*/
int emlxs_msgbuf(uintptr_t base_addr, uint_t flags, int argc,
				const mdb_arg_t *argv)
{
	uintptr_t  addr;
	emlxs_device_t device;
	uint32_t brd_no;
	emlxs_msg_log_t log;
	uint32_t count;
	uint32_t first;
	uint32_t last;
	uint32_t idx;
	uint32_t i;
	char *level;
	emlxs_msg_t msg;
	uint32_t secs;
	uint32_t hsecs;
	emlxs_msg_entry_t entry;
	char buffer[256];
	char buffer2[256];
	int32_t instance[MAX_FC_BRDS];
	char driver[32];
	int32_t instance_count;
	uint32_t ddiinst;


	if (argc != 1) {
		mdb_printf("Usage:   ::%s_msgbuf  <instance (in hex)>\n",
		    DRIVER_NAME);
		mdb_printf("mdb: try \"::help %s_msgbuf\" for more information",
		    DRIVER_NAME);

		return (DCMD_ERR);
	}

	/* Get the device address */
	mdb_snprintf(buffer, sizeof (buffer), "%s_device", DRIVER_NAME);
	if (mdb_readvar(&device, buffer) == -1) {
		mdb_snprintf(buffer2, sizeof (buffer2),
		    "%s not found.\n", buffer);
		mdb_warn(buffer2);

		mdb_snprintf(buffer2, sizeof (buffer2),
		    "Is the %s driver loaded ?\n", DRIVER_NAME);
		mdb_warn(buffer2);
		return (DCMD_ERR);
	}

	/* Get the device instance table */
	mdb_snprintf(buffer, sizeof (buffer), "%s_instance", DRIVER_NAME);
	if (mdb_readvar(&instance, buffer) == -1) {
		mdb_snprintf(buffer2, sizeof (buffer2), "%s not found.\n",
		    buffer);
		mdb_warn(buffer2);

		mdb_snprintf(buffer2, sizeof (buffer2),
		    "Is the %s driver loaded ?\n", DRIVER_NAME);
		mdb_warn(buffer2);
		return (DCMD_ERR);
	}

	/* Get the device instance count */
	mdb_snprintf(buffer, sizeof (buffer), "%s_instance_count", DRIVER_NAME);
	if (mdb_readvar(&instance_count, buffer) == -1) {
		mdb_snprintf(buffer2, sizeof (buffer2), "%s not found.\n",
		    buffer);
		mdb_warn(buffer2);

		mdb_snprintf(buffer2, sizeof (buffer2),
		    "Is the %s driver loaded ?\n", DRIVER_NAME);
		mdb_warn(buffer2);
		return (DCMD_ERR);
	}

	ddiinst = (uint32_t)mdb_strtoull(argv[0].a_un.a_str);

	for (brd_no = 0; brd_no < instance_count; brd_no++) {
		if (instance[brd_no] == ddiinst) {
			break;
		}
	}

	if (brd_no == instance_count) {
		mdb_warn("Device instance not found. ddinst=%d\n", ddiinst);
		return (DCMD_ERR);
	}

	/* Check if buffer is null */
	addr = (uintptr_t)device.log[brd_no];
	if (addr == 0) {
		mdb_warn("Device instance not found. ddinst=%d\n", ddiinst);
		return (0);
	}

	if (mdb_vread(&log, sizeof (emlxs_msg_log_t), addr) !=
	    sizeof (emlxs_msg_log_t)) {
		mdb_warn("\nUnable to read %d bytes @ %llx.\n",
		    sizeof (emlxs_msg_log_t), addr);
		return (0);
	}

	/* Check if buffer is empty */
	if (log.count == 0) {
		mdb_warn("Log buffer empty.\n");
		return (0);
	}

	/* Get last entry id saved */
	last  = log.count - 1;

	/* Check if buffer has already been filled once */
	if (log.count >= log.size) {
		first = log.count - log.size;
		idx = log.next;
	} else {
		/* Buffer not yet filled */
		first = 0;
		idx = 0;
	}

	/* Get the total number of messages available for return */
	count = last - first + 1;

	mdb_printf("\n");

	/* Print the messages */
	for (i = 0; i < count; i++) {
		if (mdb_vread(&entry, sizeof (emlxs_msg_entry_t),
		    (uintptr_t)&log.entry[idx]) != sizeof (emlxs_msg_entry_t)) {
			mdb_warn("Cannot read log entry. index=%d count=%d\n",
			    idx, count);
			return (DCMD_ERR);
		}

		if (mdb_vread(&msg, sizeof (emlxs_msg_t),
		    (uintptr_t)entry.msg) != sizeof (emlxs_msg_t)) {
			mdb_warn("Cannot read msg. index=%d count=%d\n",
			    idx, count);
			return (DCMD_ERR);
		}

		hsecs = (entry.time%100);
		secs  = entry.time/100;

		switch (msg.level) {
		case EMLXS_DEBUG:
			level = "  DEBUG";
			break;

		case EMLXS_NOTICE:
			level = " NOTICE";
			break;

		case EMLXS_WARNING:
			level = "WARNING";
			break;

		case EMLXS_ERROR:
			level = "  ERROR";
			break;

		case EMLXS_PANIC:
			level = "  PANIC";
			break;

		case EMLXS_EVENT:
			level = "  EVENT";
			break;

		default:
			level = "UNKNOWN";
			break;
		}

		if (entry.vpi == 0) {
			mdb_snprintf(driver, sizeof (driver), "%s%d",
			    DRIVER_NAME, entry.instance);
		} else {
			mdb_snprintf(driver, sizeof (driver), "%s%d.%d",
			    DRIVER_NAME, entry.instance, entry.vpi);
		}

		/* Generate the message string */
		if (msg.buffer[0] != 0) {
			if (entry.buffer[0] != 0) {
				mdb_snprintf(buffer, sizeof (buffer),
				    "%8d.%02d: "
				    "%6d:[%1X.%04X]%s:%7s:%4d: %s\n(%s)\n",
				    secs, hsecs, entry.id, entry.fileno,
				    entry.line, driver, level, msg.id,
				    msg.buffer, entry.buffer);

			} else {
				mdb_snprintf(buffer, sizeof (buffer),
				    "%8d.%02d: %6d:[%1X.%04X]%s:%7s:%4d: %s\n",
				    secs, hsecs, entry.id, entry.fileno,
				    entry.line, driver, level, msg.id,
				    msg.buffer);
			}
		} else {
			if (entry.buffer[0] != 0) {
				mdb_snprintf(buffer, sizeof (buffer),
				    "%8d.%02d: "
				    "%6d:[%1X.%04X]%s:%7s:%4d:\n(%s)\n",
				    secs, hsecs, entry.id, entry.fileno,
				    entry.line, driver, level, msg.id,
				    entry.buffer);
			} else {
				mdb_snprintf(buffer, sizeof (buffer),
				    "%8d.%02d: %6d:[%1X.%04X]%s:%7s:%4d:\n",
				    secs, hsecs, entry.id, entry.fileno,
				    entry.line, driver, level, msg.id);
			}
		}

		mdb_printf("%s", buffer);

		/* Increment index */
		if (++idx >= log.size) {
			idx = 0;
		}
	}

	mdb_printf("\n");

	return (0);

} /* emlxs_msgbuf() */
