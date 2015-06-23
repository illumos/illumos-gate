/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#define	DUMP_SUPPORT

#include <emlxs_mdb.h>
#include <emlxs_msg.h>
#include <emlxs_dump.h>
#include <emlxs_device.h>

/*
 * MDB module linkage information:
 */

static const mdb_dcmd_t dcmds[] =
{
	{ DRIVER_NAME"_msgbuf", "<instance>", "dumps the "DRIVER_NAME
	    " driver internal message buffer", emlxs_msgbuf, emlxs_msgbuf_help},
	{ DRIVER_NAME"_dump", "<type> <instance>", "dumps the "DRIVER_NAME
	    " driver firmware core", emlxs_dump, emlxs_dump_help},
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

	mdb_printf("Usage:   ::%s_msgbuf  <instance(hex)>\n\n", DRIVER_NAME);
	mdb_printf("         <instance>   This is the %s driver instance " \
	    "number in hex.\n", DRIVER_NAME);
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
	char	merge[1024];

	emlxs_msg_entry_t entry;
	char buffer[256];
	char buffer2[256];
	int32_t instance[MAX_FC_BRDS];
	char driver[32];
	int32_t instance_count;
	uint32_t ddiinst;

	if (argc != 1) {
		mdb_printf("Usage:   ::%s_msgbuf  <instance(hex)>\n",
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
				mdb_snprintf(merge, sizeof (merge),
				    "[%Y:%03d:%03d:%03d] "
				    "%6d:[%1X.%04X]%s:%7s:%4d:\n%s\n(%s)\n",
				    entry.id_time.tv_sec,
				    (int)entry.id_time.tv_nsec/1000000,
				    (int)(entry.id_time.tv_nsec/1000)%1000,
				    (int)entry.id_time.tv_nsec%1000,
				    entry.id, entry.fileno,
				    entry.line, driver, level, msg.id,
				    msg.buffer, entry.buffer);

			} else {
				mdb_snprintf(merge, sizeof (merge),
				    "[%Y:%03d:%03d:%03d] "
				    "%6d:[%1X.%04X]%s:%7s:%4d:\n%s\n",
				    entry.id_time.tv_sec,
				    (int)entry.id_time.tv_nsec/1000000,
				    (int)(entry.id_time.tv_nsec/1000)%1000,
				    (int)entry.id_time.tv_nsec%1000,
				    entry.id, entry.fileno,
				    entry.line, driver, level, msg.id,
				    msg.buffer);
			}
		} else {
			if (entry.buffer[0] != 0) {
				mdb_snprintf(merge, sizeof (merge),
				    "[%Y:%03d:%03d:%03d] "
				    "%6d:[%1X.%04X]%s:%7s:%4d:\n(%s)\n",
				    entry.id_time.tv_sec,
				    (int)entry.id_time.tv_nsec/1000000,
				    (int)(entry.id_time.tv_nsec/1000)%1000,
				    (int)entry.id_time.tv_nsec%1000,
				    entry.id, entry.fileno,
				    entry.line, driver, level, msg.id,
				    entry.buffer);

			} else {
				mdb_snprintf(merge, sizeof (merge),
				    "[%Y:%03d:%03d:%03d] "
				    "%6d:[%1X.%04X]%s:%7s:%4d:\n%s\n",
				    entry.id_time.tv_sec,
				    (int)entry.id_time.tv_nsec/1000000,
				    (int)(entry.id_time.tv_nsec/1000)%1000,
				    (int)entry.id_time.tv_nsec%1000,
				    entry.id, entry.fileno,
				    entry.line, driver, level, msg.id,
				    msg.buffer);
			}
		}

		mdb_printf("%s", merge);

		/* Increment index */
		if (++idx >= log.size) {
			idx = 0;
		}
	}

	mdb_printf("\n");

	return (0);

} /* emlxs_msgbuf() */


void
emlxs_dump_help()
{
	mdb_printf("Usage:   ::%s_dump all <instance(hex)>\n", DRIVER_NAME);
	mdb_printf("         ::%s_dump txt <instance(hex)>\n", DRIVER_NAME);
	mdb_printf("         ::%s_dump dmp <instance(hex)>\n", DRIVER_NAME);
	mdb_printf("         ::%s_dump cee <instance(hex)>\n", DRIVER_NAME);
	mdb_printf("\n");
	mdb_printf("                txt   Display firmware text summary " \
	    "file.\n");
	mdb_printf("                dmp   Display firmware dmp binary file.\n");
	mdb_printf("                cee   Display firmware cee binary file. " \
	    "(FCOE adapters only)\n");
	mdb_printf("                all   Display all firmware core files.\n");
	mdb_printf("         <instance>   This is the %s driver instance " \
	    "number in hex.\n", DRIVER_NAME);
	mdb_printf("                      (e.g. 0, 1,..., e, f, etc.)\n");

} /* emlxs_dump_help() */


/*ARGSUSED*/
int
emlxs_dump(uintptr_t base_addr, uint_t flags, int argc,
				const mdb_arg_t *argv)
{
	uintptr_t  addr;
	emlxs_device_t device;
	uint32_t brd_no;
	uint32_t i;
	char buffer[256];
	char buffer2[256];
	int32_t instance[MAX_FC_BRDS];
	int32_t instance_count;
	uint32_t ddiinst;
	uint8_t *bptr;
	char *cptr;
	emlxs_file_t dump_txtfile;
	emlxs_file_t dump_dmpfile;
	emlxs_file_t dump_ceefile;
	uint32_t size;
	uint32_t file;

	if (argc != 2) {
		goto usage;
	}

	if ((strcmp(argv[0].a_un.a_str, "all") == 0) ||
	    (strcmp(argv[0].a_un.a_str, "ALL") == 0) ||
	    (strcmp(argv[0].a_un.a_str, "All") == 0)) {
		file = 0;
	} else if ((strcmp(argv[0].a_un.a_str, "txt") == 0) ||
	    (strcmp(argv[0].a_un.a_str, "TXT") == 0) ||
	    (strcmp(argv[0].a_un.a_str, "Txt") == 0)) {
		file = 1;
	} else if ((strcmp(argv[0].a_un.a_str, "dmp") == 0) ||
	    (strcmp(argv[0].a_un.a_str, "DMP") == 0) ||
	    (strcmp(argv[0].a_un.a_str, "Dmp") == 0)) {
		file = 2;
	} else if ((strcmp(argv[0].a_un.a_str, "cee") == 0) ||
	    (strcmp(argv[0].a_un.a_str, "CEE") == 0) ||
	    (strcmp(argv[0].a_un.a_str, "Cee") == 0)) {
		file = 3;
	} else {
		goto usage;
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

	ddiinst = (uint32_t)mdb_strtoull(argv[1].a_un.a_str);

	for (brd_no = 0; brd_no < instance_count; brd_no++) {
		if (instance[brd_no] == ddiinst) {
			break;
		}
	}

	if (brd_no == instance_count) {
		mdb_warn("Device instance not found. ddinst=%d\n", ddiinst);
		return (DCMD_ERR);
	}

	if (file == 0 || file == 1) {

		addr = (uintptr_t)device.dump_txtfile[brd_no];
		if (addr == 0) {
			mdb_warn("TXT file: Device instance not found. " \
			    "ddinst=%d\n", ddiinst);
			goto dmp_file;
		}

		if (mdb_vread(&dump_txtfile, sizeof (dump_txtfile), addr)
		    != sizeof (dump_txtfile)) {
			mdb_warn("TXT file: Unable to read %d bytes @ %llx.\n",
			    sizeof (dump_txtfile), addr);
			goto dmp_file;
		}

		size = (uintptr_t)dump_txtfile.ptr -
		    (uintptr_t)dump_txtfile.buffer;

		if (size == 0) {
			mdb_printf("TXT file: Not available.\n");
			goto dmp_file;
		}
		bptr  = (uint8_t *)mdb_zalloc(size, UM_SLEEP|UM_GC);

		if (bptr == 0) {
			mdb_warn("TXT file: Unable to allocate file buffer. " \
			    "ddinst=%d size=%d\n", ddiinst, size);
			goto dmp_file;
		}

		if (mdb_vread(bptr, size, (uintptr_t)dump_txtfile.buffer)
		    != size) {
			mdb_warn("TXT file: Unable to read %d bytes @ %llx.\n",
			    size, dump_txtfile.buffer);
			goto dmp_file;
		}

		mdb_printf("<TXT File Start>\n");
		mdb_printf("\n");
		mdb_printf("%s", bptr);
		mdb_printf("\n");
		mdb_printf("<TXT File End>\n");
	}

dmp_file:

	if (file == 0 || file == 2) {
		addr = (uintptr_t)device.dump_dmpfile[brd_no];
		if (addr == 0) {
			mdb_warn("DMP file: Device instance not found. " \
			    "ddinst=%d\n", ddiinst);
			goto cee_file;
		}

		if (mdb_vread(&dump_dmpfile, sizeof (dump_dmpfile), addr)
		    != sizeof (dump_dmpfile)) {
			mdb_warn("DMP file: Unable to read %d bytes @ %llx.\n",
			    sizeof (dump_dmpfile), addr);
			goto cee_file;
		}

		size = (uintptr_t)dump_dmpfile.ptr -
		    (uintptr_t)dump_dmpfile.buffer;

		if (size == 0) {
			mdb_printf("DMP file: Not available.\n");
			goto cee_file;
		}

		bptr  = (uint8_t *)mdb_zalloc(size, UM_SLEEP|UM_GC);

		if (bptr == 0) {
			mdb_warn("DMP file: Unable to allocate file buffer. " \
			    "ddinst=%d size=%d\n", ddiinst, size);
			goto cee_file;
		}

		if (mdb_vread(bptr, size, (uintptr_t)dump_dmpfile.buffer)
		    != size) {
			mdb_warn("DMP file: Unable to read %d bytes @ %llx.\n",
			    size, dump_dmpfile.buffer);
			goto cee_file;
		}

		mdb_printf("<DMP File Start>\n");
		mdb_printf("\n");

		bzero(buffer2, sizeof (buffer2));
		cptr = buffer2;
		for (i = 0; i < size; i++) {
			if (i && !(i % 16)) {
				mdb_printf(" %s\n", buffer2);
				bzero(buffer2, sizeof (buffer2));
				cptr = buffer2;
			}

			if (!(i % 16)) {
				mdb_printf("%08X: ", i);
			}

			if (!(i % 4)) {
				mdb_printf(" ");
			}

			if ((*bptr >= 32) && (*bptr <= 126)) {
				*cptr++ = *bptr;
			} else {
				*cptr++ = '.';
			}

			mdb_printf("%02X ", *bptr++);
		}

		size = 16 - (i % 16);
		for (i = 0; size < 16 && i < size; i++) {
			if (!(i % 4)) {
				mdb_printf(" ");
			}

			mdb_printf("   ");
		}
		mdb_printf(" %s\n", buffer2);
		mdb_printf("\n");
		mdb_printf("<DMP File End>\n");
	}

cee_file:

	if (file == 0 || file == 3) {

		addr = (uintptr_t)device.dump_ceefile[brd_no];
		if (addr == 0) {
			mdb_warn("CEE file: Device instance not found. " \
			    "ddinst=%d\n", ddiinst);
			goto done;
		}

		if (mdb_vread(&dump_ceefile, sizeof (dump_ceefile), addr)
		    != sizeof (dump_ceefile)) {
			mdb_warn("CEE file: Unable to read %d bytes @ %llx.\n",
			    sizeof (dump_ceefile), addr);
			goto done;
		}

		size = (uintptr_t)dump_ceefile.ptr -
		    (uintptr_t)dump_ceefile.buffer;

		if (size == 0) {
			mdb_printf("CEE file: Not available.\n");
			goto done;
		}

		bptr  = (uint8_t *)mdb_zalloc(size, UM_SLEEP|UM_GC);

		if (bptr == 0) {
			mdb_warn("CEE file: Unable to allocate file buffer. " \
			    "ddinst=%d size=%d\n", ddiinst, size);
			goto done;
		}

		if (mdb_vread(bptr, size, (uintptr_t)dump_ceefile.buffer)
		    != size) {
			mdb_warn("CEE file: Unable to read %d bytes @ %llx.\n",
			    size, dump_ceefile.buffer);
			goto done;
		}

		mdb_printf("<CEE File Start>\n");
		mdb_printf("\n");

		bzero(buffer2, sizeof (buffer2));
		cptr = buffer2;
		for (i = 0; i < size; i++) {
			if (i && !(i % 16)) {
				mdb_printf(" %s\n", buffer2);
				bzero(buffer2, sizeof (buffer2));
				cptr = buffer2;
			}

			if (!(i % 16)) {
				mdb_printf("%08X: ", i);
			}

			if (!(i % 4)) {
				mdb_printf(" ");
			}

			if ((*bptr >= 32) && (*bptr <= 126)) {
				*cptr++ = *bptr;
			} else {
				*cptr++ = '.';
			}

			mdb_printf("%02X ", *bptr++);
		}

		size = 16 - (i % 16);
		for (i = 0; size < 16 && i < size; i++) {
			if (!(i % 4)) {
				mdb_printf(" ");
			}

			mdb_printf("   ");
		}
		mdb_printf(" %s\n", buffer2);
		mdb_printf("\n");
		mdb_printf("<CEE File End>\n");
	}
done:

	mdb_printf("\n");
	return (0);

usage:
	mdb_printf("Usage:   ::%s_dump <file> <instance (hex)>\n",
	    DRIVER_NAME);
	mdb_printf("mdb: try \"::help %s_dump\" for more information",
	    DRIVER_NAME);

	return (DCMD_ERR);

} /* emlxs_dump() */
