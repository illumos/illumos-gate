/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018 by Chelsio Communications, Inc.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <strings.h>
#include <sys/varargs.h>
#include <errno.h>
#include <sys/byteorder.h>
#include <inttypes.h>
#include <sys/sysmacros.h>
#include <err.h>
#include <libdevinfo.h>

#include "t4nex.h"
#include "version.h"
#include "osdep.h"
#include "t4fw_interface.h"
#include "cudbg.h"
#include "cudbg_lib_common.h"

#define CUDBG_SIZE (32 * 1024 * 1024)
#define CUDBG_MAX_ENTITY_STR_LEN 4096
#define MAX_PARAM_LEN 4096

static char cxgbetool_nexus[PATH_MAX];

char *option_list[] = {
	"--collect",
	"--view",
	"--version",
};

enum {
	CUDBG_OPT_COLLECT,
	CUDBG_OPT_VIEW,
	CUDBG_OPT_VERSION,
};

/*
 * Firmware Device Log Dumping
 */

static const char * const devlog_level_strings[] = {
	[FW_DEVLOG_LEVEL_EMERG]		= "EMERG",
	[FW_DEVLOG_LEVEL_CRIT]		= "CRIT",
	[FW_DEVLOG_LEVEL_ERR]		= "ERR",
	[FW_DEVLOG_LEVEL_NOTICE]	= "NOTICE",
	[FW_DEVLOG_LEVEL_INFO]		= "INFO",
	[FW_DEVLOG_LEVEL_DEBUG]		= "DEBUG"
};

static const char * const devlog_facility_strings[] = {
	[FW_DEVLOG_FACILITY_CORE]	= "CORE",
	[FW_DEVLOG_FACILITY_CF]		= "CF",
	[FW_DEVLOG_FACILITY_SCHED]	= "SCHED",
	[FW_DEVLOG_FACILITY_TIMER]	= "TIMER",
	[FW_DEVLOG_FACILITY_RES]	= "RES",
	[FW_DEVLOG_FACILITY_HW]		= "HW",
	[FW_DEVLOG_FACILITY_FLR]	= "FLR",
	[FW_DEVLOG_FACILITY_DMAQ]	= "DMAQ",
	[FW_DEVLOG_FACILITY_PHY]	= "PHY",
	[FW_DEVLOG_FACILITY_MAC]	= "MAC",
	[FW_DEVLOG_FACILITY_PORT]	= "PORT",
	[FW_DEVLOG_FACILITY_VI]		= "VI",
	[FW_DEVLOG_FACILITY_FILTER]	= "FILTER",
	[FW_DEVLOG_FACILITY_ACL]	= "ACL",
	[FW_DEVLOG_FACILITY_TM]		= "TM",
	[FW_DEVLOG_FACILITY_QFC]	= "QFC",
	[FW_DEVLOG_FACILITY_DCB]	= "DCB",
	[FW_DEVLOG_FACILITY_ETH]	= "ETH",
	[FW_DEVLOG_FACILITY_OFLD]	= "OFLD",
	[FW_DEVLOG_FACILITY_RI]		= "RI",
	[FW_DEVLOG_FACILITY_ISCSI]	= "ISCSI",
	[FW_DEVLOG_FACILITY_FCOE]	= "FCOE",
	[FW_DEVLOG_FACILITY_FOISCSI]	= "FOISCSI",
	[FW_DEVLOG_FACILITY_FOFCOE]	= "FOFCOE",
	[FW_DEVLOG_FACILITY_CHNET]	= "CHNET",
};

static const char *progname;
int set_dbg_entity(u8 *dbg_bitmap, char *dbg_entity_list);

static int check_option(char *opt)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(option_list); i++) {
		if (!strcmp(opt, option_list[i]))
			return i;
	}
	return -1;
}

static void usage(FILE *fp)
{
	fprintf(fp, "Usage: %s <t4nex# | cxgbe#> [operation]\n", progname);
	fprintf(fp,
	    "\tdevlog                              show device log\n"
	    "\tloadfw <FW image>                   Flash the FW image\n"
	    "\tcudbg <option> [<args>]             Chelsio Unified Debugger\n");
	exit(fp == stderr ? 1 : 0);
}

static int
doit(const char *iff_name, unsigned long cmd, void *data)
{
	int fd = 0;
	int rc = 0;

	if ((fd = open(iff_name, O_RDWR)) < 0)
		return (-1);

	rc = (ioctl(fd, cmd, data) < 0) ? errno : rc;
	close(fd);
	return (rc);
}

static void
get_devlog(int argc, char *argv[], int start_arg, const char *iff_name)
{
	struct t4_devlog *devlog;
	struct fw_devlog_e *entry, *buf;
	int rc = 0, first = 0, nentries, i, j, len;
	uint64_t ftstamp = UINT64_MAX;

	devlog = malloc(T4_DEVLOG_SIZE + sizeof (struct t4_devlog));
	if (!devlog)
		err(1, "%s: can't allocate devlog buffer", __func__);

	devlog->len = T4_DEVLOG_SIZE;
	/* Get device log */
	rc = doit(iff_name, T4_IOCTL_DEVLOG, devlog);
	if (rc == ENOBUFS) {
		/*
		 * Default buffer size is not sufficient to hold device log.
		 * Driver has updated the devlog.len to indicate the expected
		 * size. Free the currently allocated devlog.data, allocate
		 * again with right size and retry.
		 */
		len = devlog->len;
		free(devlog);

		if ((devlog = malloc(len + sizeof (struct t4_devlog))) == NULL)
			err(1, "%s: can't reallocate devlog buffer", __func__);

		rc = doit(iff_name, T4_IOCTL_DEVLOG, devlog);
	}
	if (rc) {
		free(devlog);
		errx(1, "%s: can't get device log", __func__);
	}

	/* There are nentries number of entries in the buffer */
	nentries = (devlog->len / sizeof (struct fw_devlog_e));

	buf = (struct fw_devlog_e *)devlog->data;

	/* Find the first entry */
	for (i = 0; i < nentries; i++) {
		entry = &buf[i];

		if (entry->timestamp == 0)
			break;

		entry->timestamp = BE_64(entry->timestamp);
		entry->seqno = BE_32(entry->seqno);
		for (j = 0; j < 8; j++)
			entry->params[j] = BE_32(entry->params[j]);

		if (entry->timestamp < ftstamp) {
			ftstamp = entry->timestamp;
			first = i;
		}
	}

	printf("%10s  %15s  %8s  %8s  %s\n", "Seq#", "Tstamp", "Level",
	    "Facility", "Message");

	i = first;

	do {
		entry = &buf[i];

		if (entry->timestamp == 0)
			break;

		printf("%10d  %15llu  %8s  %8s  ", entry->seqno,
		    entry->timestamp,
		    (entry->level < ARRAY_SIZE(devlog_level_strings) ?
		    devlog_level_strings[entry->level] : "UNKNOWN"),
		    (entry->facility < ARRAY_SIZE(devlog_facility_strings) ?
		    devlog_facility_strings[entry->facility] : "UNKNOWN"));

		printf((const char *)entry->fmt, entry->params[0],
		    entry->params[1], entry->params[2], entry->params[3],
		    entry->params[4], entry->params[5], entry->params[6],
		    entry->params[7]);

		if (++i == nentries)
			i = 0;

	} while (i != first);

	free(devlog);
}

static void
load_fw(int argc, char *argv[], int start_arg, const char *iff_name)
{
	const char *fname = argv[start_arg];
	struct t4_ldfw *fw;
	struct stat sb;
	size_t len;
	int fd;

	if (argc != 4)
		errx(1, "incorrect number of arguments");

	fd = open(fname, O_RDONLY);
	if (fd < 0)
		err(1, "%s: opening %s failed", __func__, fname);
	if (fstat(fd, &sb) < 0) {
		warn("%s: fstat %s failed", __func__, fname);
		close(fd);
		exit(1);
	}
	len = (size_t)sb.st_size;

	fw = malloc(sizeof (struct t4_ldfw) + len);
	if (!fw) {
		warn("%s: %s allocate %zu bytes failed",
		    __func__, fname, sizeof (struct t4_ldfw) + len);
		close(fd);
		exit(1);
	}

	if (read(fd, fw->data, len) < len) {
		warn("%s: %s read failed", __func__, fname);
		close(fd);
		free(fw);
		exit(1);
	}

	close(fd);

	fw->len = len;

	if (doit(iff_name, T4_IOCTL_LOAD_FW, fw)) {
		free(fw);
		err(1, "%s: IOCTL failed", __func__);
	} else {
		printf("FW flash success, reload driver/reboot to take "
		    "effect\n");
	}

	free(fw);
}

int read_input_file(char *in_file, void **buf, int *buf_size)
{
	FILE *fptr = NULL;
	size_t count;
	int rc = 0;

	fptr = fopen(in_file, "rb");
	if (!fptr) {
		perror("error in opening file ");
		rc = -1;
		goto out;
	}
	rc = fseek(fptr, 0, SEEK_END);
	if (rc < 0) {
		perror("error in seeking file ");
		rc = -1;
		goto out;
	}
	*buf_size = ftell(fptr);
	rc = fseek(fptr, 0, SEEK_SET);
	if (rc < 0) {
		perror("error in seeking file ");
		rc = -1;
		goto out;
	}
	*buf = (void *) malloc(*buf_size);
	if (*buf == NULL) {
		rc = CUDBG_STATUS_NOSPACE;
		goto out;
	}
	memset(*buf, 0, *buf_size);

	count = fread(*buf, 1, *buf_size, fptr);
	if (count != *buf_size) {
		perror("error in reading from file ");
		goto out;
	}

out:
	if (fptr)
		fclose(fptr);

	return rc;
}

static void
do_collect(char *dbg_entity_list, const char *iff_name, const char *fname)
{
	struct t4_cudbg_dump *cudbg;
	int fd;

	cudbg = malloc(sizeof(struct t4_cudbg_dump) + CUDBG_SIZE);
	if (!cudbg) {
		err(1, "%s:allocate %d bytes failed", __func__, CUDBG_SIZE);
	}

	memset(cudbg, 0, sizeof(struct t4_cudbg_dump) + CUDBG_SIZE);

	cudbg->len = CUDBG_SIZE;

	set_dbg_entity(cudbg->bitmap, dbg_entity_list);

	if (doit(iff_name, T4_IOCTL_GET_CUDBG, cudbg)) {
		free(cudbg);
		err(1, "%s: IOCTL failed", __func__);
	}

	fd = open(fname, O_CREAT | O_TRUNC | O_EXCL | O_WRONLY,
		  S_IRUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		err(1, "%s: file open failed", __func__);
	}

	write(fd, cudbg->data, cudbg->len);
	close(fd);
	free(cudbg);
}

static void
do_view(char *dbg_entity_list, char *in_file)
{
	void *handle = NULL;
	void *buf = NULL;
	int buf_size = 32 * 1024 * 1024;
	int  next_offset = 0;
	int data_len;
	int rc = 0;

	handle = cudbg_alloc_handle();
	if (!handle)
		goto out;
	/* rcad from file */
	rc = read_input_file(in_file, &buf, &buf_size);
	if (rc < 0) {
		goto out;
	}

	set_dbg_entity(((struct cudbg_private *)handle)->dbg_init.dbg_bitmap,
			dbg_entity_list);
	do {
		if (buf_size - next_offset <= 0)
			break;

		data_len = cudbg_view(handle, buf+next_offset,
				buf_size-next_offset, NULL, 0);
		next_offset += data_len;
		if (data_len > 0)
			printf("\n\t\t<========================END============="\
					"===========>\t\t\n\n\n");
	} while (data_len > 0);

out:
	if (buf)
		free(buf);
	if (handle)
		cudbg_free_handle(handle);
	return;
}

typedef void (*cudbg_alias_get_entities_cb)(char *dst, u32 dst_size);

struct entity_access_list {
        const char *name;
        cudbg_alias_get_entities_cb get_entities_cb;
};

void
cudbg_append_string(char *dst, u32 dst_size, char *src)
{
        strlcat(dst, src, dst_size);
        strlcat(dst, ",", dst_size);
}

static void
cudbg_alias_get_allregs(char *dst, u32 dst_size)
{
        u32 i;

        for (i = 0; i < ARRAY_SIZE(entity_list); i++)
                if (entity_list[i].flag & (1 << ENTITY_FLAG_REGISTER))
                        cudbg_append_string(dst, dst_size, entity_list[i].name);
}

static struct entity_access_list ATTRIBUTE_UNUSED entity_alias_list[] = {
        {"allregs", cudbg_alias_get_allregs},
};

static int
check_dbg_entity(char *entity)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(entity_list); i++)
		if (!strcmp(entity, entity_list[i].name))
			return entity_list[i].bit;
	return -1;
}

/* Get matching alias index from entity_alias_list[] */
static 
int get_alias(const char *entity)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(entity_alias_list); i++)
		if (!strcmp(entity, entity_alias_list[i].name))
			return i;
	return -1;
}

static int
parse_entity_list(const char *dbg_entity_list, char *dst,
				    u32 dst_size)
{
	char *tmp_dbg_entity_list;
	char *dbg_entity;
	int rc, i;

	/* Holds single entity name de-limited by comma */
	tmp_dbg_entity_list = malloc(CUDBG_MAX_ENTITY_STR_LEN);
	if (!tmp_dbg_entity_list)
		return ENOMEM;

	strlcpy(tmp_dbg_entity_list, dbg_entity_list, CUDBG_MAX_ENTITY_STR_LEN);
	dbg_entity = strtok(tmp_dbg_entity_list, ",");
	while (dbg_entity != NULL) {
		/* See if specified entity name exists.  If it doesn't
		 * exist, see if the entity name is an alias.
		 * If it's not a valid entity name, bail with error.
		 */
		rc = check_dbg_entity(dbg_entity);
		if (rc < 0) {
			i = get_alias(dbg_entity);
			if (i < 0) {
				/* Not an alias, and not a valid entity name */
				printf("\nUnknown entity: %s\n", dbg_entity);
				rc = CUDBG_STATUS_ENTITY_NOT_FOUND;
				goto out_err;
			} else {
				/* If alias is found, get all the corresponding
				 * debug entities related to the alias.
				 */
				entity_alias_list[i].get_entities_cb(dst, dst_size);
			}
		} else {
			/* Not an alias, but is a valid entity name.
			 * So, append the corresponding debug entity.
			 */
			cudbg_append_string(dst, dst_size, entity_list[rc].name);
		}
		dbg_entity = strtok(NULL, ",");
	}

	rc = 0;

out_err:
	free(tmp_dbg_entity_list);
	return rc;
}

static
int get_entity_list(const char *in_buff, char **out_buff)
{
	char *dbg_entity_list;
	int rc;

	/* Allocate enough to hold converted alias string.
	 * Must be freed by caller
	 */
	dbg_entity_list = malloc(CUDBG_MAX_ENTITY_STR_LEN);
	if (!dbg_entity_list)
		return ENOMEM;

	memset(dbg_entity_list, 0, CUDBG_MAX_ENTITY_STR_LEN);
	rc = parse_entity_list(in_buff, dbg_entity_list,
			       CUDBG_MAX_ENTITY_STR_LEN);
	if (rc) {
		free(dbg_entity_list);
		return rc;
	}

	/* Remove the last comma */
	dbg_entity_list[strlen(dbg_entity_list) - 1] = '\0';
	*out_buff = dbg_entity_list;
	return 0;
}

static void
put_entity_list(char *buf)
{
	if (buf)
		free(buf);
}

int
set_dbg_entity(u8 *dbg_bitmap, char *dbg_entity_list)
{
	int i, dbg_entity_bit, rc = 0;
	char *dbg_entity;
	char *dbg_entity_list_tmp;

	dbg_entity_list_tmp = malloc(MAX_PARAM_LEN);
	if (!dbg_entity_list_tmp) {
		rc = CUDBG_STATUS_NOSPACE;
		return rc;
	}

	if (dbg_entity_list != NULL) {
		strlcpy(dbg_entity_list_tmp, dbg_entity_list, MAX_PARAM_LEN);
		dbg_entity = strtok(dbg_entity_list_tmp, ",");
	}
	else
		dbg_entity = NULL;

	while (dbg_entity != NULL) {
		rc = check_dbg_entity(dbg_entity);
		if (rc < 0) {
			printf("\n\tInvalid debug entity: %s\n", dbg_entity);
			//Vishal cudbg_usage();
			goto out_free;
		}

		dbg_entity_bit = rc;

		if (dbg_entity_bit == CUDBG_ALL) {
			for (i = 1; i < CUDBG_MAX_ENTITY; i++)
				set_dbg_bitmap(dbg_bitmap, i);
			set_dbg_bitmap(dbg_bitmap, CUDBG_ALL);
			break;
		} else {
			set_dbg_bitmap(dbg_bitmap, dbg_entity_bit);
		}

		dbg_entity = strtok(NULL, ",");
	}

	rc = 0;

out_free:
	free(dbg_entity_list_tmp);
	return rc;
}


static void
get_cudbg(int argc, char *argv[], int start_arg, const char *iff_name)
{
	char *dbg_entity_list = NULL;
	int rc = 0, option;

	if (start_arg >= argc)
		errx(1, "no option provided");

	rc = check_option(argv[start_arg++]);
	if (rc < 0) {
		errx(1, "%s:Invalid option provided", __func__);
	}
	option = rc;

	if (option == CUDBG_OPT_VERSION) {
		printf("Library Version %d.%d.%d\n", CUDBG_MAJOR_VERSION,
			CUDBG_MINOR_VERSION, CUDBG_BUILD_VERSION);
		return;
	}

	if (argc < 5) {
		errx(1, "Invalid number of arguments\n");
	}
	rc = get_entity_list(argv[start_arg++],
			     &dbg_entity_list);
	if (rc) {
		errx(1, "Error in parsing entity\n");
	}

	if (argc < 6) {
		errx(1, "File name is missing\n");
	}

	switch (option) {
		case CUDBG_OPT_COLLECT:
			do_collect(dbg_entity_list, iff_name, argv[start_arg]);
			break;
		case CUDBG_OPT_VIEW:
			do_view(dbg_entity_list, argv[start_arg]);
			break;
		default:
			errx(1, "Wrong option provided\n");
	}

	put_entity_list(dbg_entity_list);
}

static void
run_cmd(int argc, char *argv[], const char *iff_name)
{
	if (strcmp(argv[2], "devlog") == 0)
		get_devlog(argc, argv, 3, iff_name);
	else if (strcmp(argv[2], "loadfw") == 0)
		load_fw(argc, argv, 3, iff_name);
	else if (strcmp(argv[2], "cudbg") == 0)
		get_cudbg(argc, argv, 3, iff_name);
	else
		usage(stderr);
}

/*
 * Traditionally we expect to be given a path to the t4nex device control file
 * hidden in /devices. To make life easier, we want to also support folks using
 * the driver instance numbers for either a given t4nex%d or cxgbe%d. We check
 * to see if we've been given a path to a character device and if so, just
 * continue straight on with the given argument. Otherwise we attempt to map it
 * to something known.
 */
static const char *
cxgbetool_parse_path(char *arg)
{
	struct stat st;
	di_node_t root, node;
	const char *numptr, *errstr;
	size_t drvlen;
	int inst;
	boolean_t is_t4nex = B_TRUE;
	char mname[64];

	if (stat(arg, &st) == 0) {
		if (S_ISCHR(st.st_mode)) {
			return (arg);
		}
	}

	if (strncmp(arg, T4_NEXUS_NAME, sizeof (T4_NEXUS_NAME) - 1) == 0) {
		drvlen = sizeof (T4_NEXUS_NAME) - 1;
	} else if (strncmp(arg, T4_PORT_NAME, sizeof (T4_PORT_NAME) - 1) == 0) {
		is_t4nex = B_FALSE;
		drvlen = sizeof (T4_PORT_NAME) - 1;
	} else {
		errx(EXIT_FAILURE, "cannot use device %s: not a character "
		    "device or a %s/%s device instance", arg, T4_PORT_NAME,
		    T4_NEXUS_NAME);
	}

	numptr = arg + drvlen;
	inst = (int)strtonum(numptr, 0, INT_MAX, &errstr);
	if (errstr != NULL) {
		errx(EXIT_FAILURE, "failed to parse instance number '%s': %s",
		    numptr, errstr);
	}

	/*
	 * Now that we have the instance here, we need to truncate the string at
	 * the end of the driver name otherwise di_drv_first_node() will be very
	 * confused as there is no driver called say 't4nex0'.
	 */
	arg[drvlen] = '\0';
	root = di_init("/", DINFOCPYALL);
	if (root == DI_NODE_NIL) {
		err(EXIT_FAILURE, "failed to initialize libdevinfo while "
		    "trying to map device name %s", arg);
	}

	for (node = di_drv_first_node(arg, root); node != DI_NODE_NIL;
	    node = di_drv_next_node(node)) {
		char *bpath;
		di_minor_t minor = DI_MINOR_NIL;

		if (di_instance(node) != inst) {
			continue;
		}

		if (!is_t4nex) {
			const char *pdrv;
			node = di_parent_node(node);
			pdrv = di_driver_name(node);
			if (pdrv == NULL || strcmp(pdrv, T4_NEXUS_NAME) != 0) {
				errx(EXIT_FAILURE, "%s does not have %s "
				    "parent, found %s%d", arg, T4_NEXUS_NAME,
				    pdrv != NULL ? pdrv : "unknown",
				    pdrv != NULL ? di_instance(node) : -1);
			}
		}

		(void) snprintf(mname, sizeof (mname), "%s,%d", T4_NEXUS_NAME,
		    di_instance(node));

		while ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
			if (strcmp(di_minor_name(minor), mname) == 0) {
				break;
			}
		}

		if (minor == DI_MINOR_NIL) {
			errx(EXIT_FAILURE, "failed to find minor %s on %s%d",
			    mname, di_driver_name(node), di_instance(node));
		}

		bpath = di_devfs_minor_path(minor);
		if (bpath == NULL) {
			err(EXIT_FAILURE, "failed to get minor path for "
			    "%s%d:%s", di_driver_name(node), di_instance(node),
			    di_minor_name(minor));
		}
		if (snprintf(cxgbetool_nexus, sizeof (cxgbetool_nexus),
		    "/devices%s", bpath) >= sizeof (cxgbetool_nexus)) {
			errx(EXIT_FAILURE, "failed to construct full /devices "
			    "path for %s: internal path buffer would have "
			    "overflowed", bpath);
		}
		di_devfs_path_free(bpath);

		di_fini(root);
		return (cxgbetool_nexus);
	}

	errx(EXIT_FAILURE, "failed to map %s%d to a %s or %s instance",
	    arg, inst, T4_PORT_NAME, T4_NEXUS_NAME);
}

int
main(int argc, char *argv[])
{
	const char *iff_name;

	progname = argv[0];

	if (argc == 2) {
		if (strcmp(argv[1], "-h") == 0 ||
		    strcmp(argv[1], "--help") == 0) {
			usage(stdout);
		}

		if (strcmp(argv[1], "-v") == 0 ||
		    strcmp(argv[1], "--version") == 0) {
			printf("cxgbetool version %s\n", DRV_VERSION);
			exit(0);
		}
	}

	if (argc < 3)
		usage(stderr);

	iff_name = cxgbetool_parse_path(argv[1]);

	run_cmd(argc, argv, iff_name);

	return (0);
}
