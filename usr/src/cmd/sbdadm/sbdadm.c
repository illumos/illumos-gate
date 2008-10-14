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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libintl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <strings.h>
#include <ctype.h>
#include <libnvpair.h>

#include <cmdparse.h>
#include <sys/stmf_defines.h>
#include <libstmf.h>
#include <sys/stmf_sbd_ioctl.h>

#define	BIG_BUF_SIZE	512
#define	MAX_LU_LIST	8192
#define	LU_LIST_MAX_RETRIES 3

uint8_t big_buf[BIG_BUF_SIZE];

int delete_lu(int argc, char *argv[], cmdOptions_t *options,
    void *callData);
int create_lu(int argc, char *argv[], cmdOptions_t *options, void *callData);
int import_lu(int argc, char *argv[], cmdOptions_t *options, void *callData);
int list_lus(int argc, char *argv[], cmdOptions_t *options, void *callData);
int modify_lu(int argc, char *argv[], cmdOptions_t *options, void *callData);
static int persist_lu_register(char *, char *);
int print_lu_attr(uint64_t handle, char **s);
void print_guid(uint8_t *g, FILE *f);
void print_attr_header();

char	*rlc_ret[] = {	"", "Metadata creation failed",
	"LU is not initialized",
	"File is already loaded",
	"GUID in the file is already registered",
	"Registration with framework failed",
	"Deregistration with stmf failed",
	"Unable to lookup file",
	"Incorrect file type to export as LU. Only regular \n"
	    "files and raw storage devices (disks/volumes) can be exported "
	    "as LUs",
	"Unable to open file",
	"Unable to get file attributes",
	"File size has to be at least 1M",
	"File size is not a multiple of blocksize",
	"LU size is out of range",
	"LU size is not supported by underlying Filesystem"
};

char sbdadm_ver[] = "sbdadm version 1.0";

optionTbl_t options[] = {
	{ "disk-size", required_argument, 's',
			"Size with <none>/k/m/g/t/p/e modifier" },
	{ "keep-views", no_arg, 'k',
			"Dont delete view entries related to the LU" },
	{ NULL, 0, 0 }
};

subCommandProps_t subCommands[] = {
	{ "create-lu", create_lu, "s", NULL, NULL,
		OPERAND_MANDATORY_SINGLE,
		"Full path of the file to initialize" },
	{ "delete-lu", delete_lu, "k", NULL, NULL,
		OPERAND_MANDATORY_SINGLE, "GUID of the LU to deregister" },
	{ "import-lu", import_lu, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, "filename of the LU to import" },
	{ "list-lu", list_lus, NULL, NULL, NULL,
		OPERAND_NONE, "List all the exported LUs" },
	{ "modify-lu", modify_lu, "s", "s", NULL,
		OPERAND_MANDATORY_SINGLE,
		"Full path of the LU or GUID of a registered LU" },
	{ NULL, 0, 0, NULL, 0, NULL}
};

int sbd_fd;

int
main(int argc, char *argv[])
{
	int ret, func_ret;
	synTables_t sbdt = { sbdadm_ver, options, subCommands };

	sbd_fd = open("/devices/pseudo/stmf_sbd@0:admin", O_RDONLY);
	if (sbd_fd < 0) {
		if (errno == EPERM) {
			(void) fprintf(stderr, "Not enough permissions to open "
			    "device\n");
		} else {
			(void) fprintf(stderr,
			    "Unable to open device. Is the driver "
			    "attached ?\n");
		}
		exit(1);
	}
	ret = cmdParse(argc, argv, sbdt, NULL, &func_ret);

	if (ret)
		return (ret);
	return (func_ret);
}

/*
 * Supports upto 8 Exabytes.
 *
 * Returns zero upon success and the size in sizep.
 * returns 2 if the string format is invalid.
 * returns 1 if the specified size is out of range.
 */
int
str_to_size(char *str, uint64_t *sizep)
{
	uint64_t cur_size, m;
	uint64_t new_cur_size;
	int i;
	char c;

	m = 1;
	cur_size = 0;

	for (i = 0; str[i] != NULL; i++) {
		if (m != 1) {
			/* We should have been done after the modifier */
			return (2);
		}
		c = str[i];
		if (isdigit(c)) {
			new_cur_size = (cur_size * 10) +
			    (((uint64_t)c) - '0');
			if (new_cur_size < cur_size) {
				/* Overflow */
				return (1);
			}
			cur_size = new_cur_size;
			continue;
		}
		if (cur_size == 0) {
			/* Direct format modifier ?? */
			return (2);
		}
		c = toupper(c);
		if (c == 'K') {
			m = 1024;
		} else if (c == 'M') {
			m = 1024 * 1024;
		} else if (c == 'G') {
			m = 1024 * 1024 * 1024;
		} else if (c == 'T') {
			m = 1024ll * 1024 * 1024 * 1024;
		} else if (c == 'P') {
			m = 1024ll * 1024 * 1024 * 1024 * 1024;
		} else if (c == 'E') {
			m = 1024ll * 1024 * 1024 * 1024 * 1024 * 1024;
		} else {
			return (2);
		}
	}

	while (m > 1) {
		if (cur_size & 0x8000000000000000ull) {
			/* Overflow */
			return (1);
		}
		cur_size <<= 1;
		m >>= 1;
	}

	if (cur_size > 0x8000000000000000ull) {
		/* We cannot allow more than 8 Exabytes */
		return (1);
	}

	*sizep = cur_size;

	return (0);
}

static int
persist_lu_register(char *guid, char *filename)
{
	int ret = 0;
	nvlist_t *nvl = NULL;
	uint64_t setToken;
	boolean_t		retryGetProviderData;

	do {
		retryGetProviderData = B_FALSE;
		ret = stmfGetProviderDataProt("sbd", &nvl,
		    STMF_LU_PROVIDER_TYPE, &setToken);
		if (ret != STMF_STATUS_SUCCESS) {
			if (ret == STMF_ERROR_NOT_FOUND) {
				(void) nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
			} else {
				(void) fprintf(stderr,
				    "could not access persistent store\n");
				ret = 1;
				goto out;
			}
		}

		ret = nvlist_add_string(nvl, guid, filename);
		if (ret != 0) {
			(void) fprintf(stderr,
			    "could not add data to nvlist\n");
			ret = 1;
			goto out;
		}

		ret = stmfSetProviderDataProt("sbd", nvl, STMF_LU_PROVIDER_TYPE,
		    &setToken);
		if (ret != STMF_STATUS_SUCCESS) {
			if (ret == STMF_ERROR_BUSY) {
				(void) fprintf(stderr,
				    "stmf framework resource busy\n");
			} else if (ret == STMF_ERROR_PROV_DATA_STALE) {
				nvlist_free(nvl);
				nvl = NULL;
				retryGetProviderData = B_TRUE;
				continue;
			} else {
				(void) fprintf(stderr,
				    "unable to set persistent store data\n");
			}
			ret = 1;
			goto out;
		}
	} while (retryGetProviderData);
out:
	nvlist_free(nvl);
	return (ret);
}

/*ARGSUSED*/
int
create_lu(int argc, char *argv[], cmdOptions_t *options, void *callData)
{
	register_lu_cmd_t *rlc;
	uint32_t fl;
	int ret = 0, err;
	uint64_t size;
	char guidAsciiBuf[33];

	/* Check whether this file path is absolute path */
	if (argv[argc - 1][0] != '/') {
		(void) fprintf(stderr, "File name should be an absolute path"
		    " i.e. it should start with a /\n");
		return (1);
	}

	fl = strlen(argv[argc - 1]) + 1;
	rlc = (register_lu_cmd_t *)malloc(sizeof (register_lu_cmd_t) + fl - 8);
	if (rlc == NULL) {
		(void) fprintf(stderr, "Unable to allocate memory\n");
		return (1);
	}
	bzero(rlc, sizeof (register_lu_cmd_t));
	rlc->total_struct_size = sizeof (register_lu_cmd_t) + fl - 8;

	rlc->flags = RLC_LU_TYPE_FILEDISK | RLC_CREATE_LU | RLC_REGISTER_LU;
	for (; options->optval; options++) {
		if (options->optval == 's') {
			err = str_to_size(options->optarg, &size);
			if (err == 1) {
				(void) fprintf(stderr,
				    "Size out of range: maximum"
				    " supported size is 9223372036854710272"
				    " (8 Exabytes - 64 Kilobytes)\n");
				ret = 1;
				goto create_lu_done;
			} else if (err == 2) {
				(void) fprintf(stderr,
				    "Invalid size specified\n");
				ret = 1;
				goto create_lu_done;
			}
			rlc->lu_size = size;
		}
	}
	(void) strcpy(rlc->name, argv[argc-1]);
	if ((ioctl(sbd_fd, SBD_REGISTER_LU, rlc) < 0) ||
	    (rlc->return_code != 0) || (rlc->op_ret != STMF_SUCCESS)) {
		if (rlc->return_code && (rlc->return_code < RLC_RET_MAX_VAL)) {
			(void) fprintf(stderr, "LU Create failed : %s.\n",
			    rlc_ret[rlc->return_code]);
			if (rlc->return_code ==
			    RLC_RET_SIZE_NOT_SUPPORTED_BY_FS) {
				(void) fprintf(stderr, "Maximum LU size on "
				    "the underlying filesystem can be %llu "
				    "bytes.\n",
				    ((((uint64_t)1) << rlc->filesize_nbits)
				    - 1 - 64 * 1024) & 0xfffffffffffffe00ull);
			}
			if (rlc->return_code ==
			    RLC_RET_GUID_ALREADY_REGISTERED) {
				(void) fprintf(stderr, "Registered GUID is ");
				print_guid(rlc->guid, stderr);
				(void) fprintf(stderr, "\n");
			}
		} else {
			(void) fprintf(stderr, "LU Create failed(%llx) : %s.\n",
			    rlc->op_ret, strerror(errno));
		}
		ret = 1;
	} else {
		if (rlc->flags & RLC_REGISTER_LU) {
			(void) printf("\nCreated the following LU:\n");
			print_attr_header();
			(void) print_lu_attr(rlc->lu_handle, NULL);
			(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
			    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
			    "%02x%02x%02x%02x%02x%02x",
			    rlc->guid[0], rlc->guid[1], rlc->guid[2],
			    rlc->guid[3], rlc->guid[4], rlc->guid[5],
			    rlc->guid[6], rlc->guid[7], rlc->guid[8],
			    rlc->guid[9], rlc->guid[10], rlc->guid[11],
			    rlc->guid[12], rlc->guid[13], rlc->guid[14],
			    rlc->guid[15]);

			ret = persist_lu_register(guidAsciiBuf, argv[argc - 1]);
		}
	}

create_lu_done:;
	free(rlc);
	return (ret);
}

/*ARGSUSED*/
int
import_lu(int argc, char *argv[], cmdOptions_t *options, void *callData)
{
	register_lu_cmd_t *rlc;
	uint32_t fl;
	int ret = 0;
	char guidAsciiBuf[33];

	/* Check whether this file path is absolute path */
	if (argv[argc - 1][0] != '/') {
		(void) fprintf(stderr, "File name should be an absolute path"
		    " i.e. it should start with a /\n");
		return (1);
	}

	fl = strlen(argv[argc - 1]) + 1;
	rlc = (register_lu_cmd_t *)malloc(sizeof (register_lu_cmd_t) + fl - 8);
	if (rlc == NULL) {
		(void) fprintf(stderr, "Unable to allocate memory\n");
		return (1);
	}
	bzero(rlc, sizeof (register_lu_cmd_t));
	rlc->total_struct_size = sizeof (register_lu_cmd_t) + fl - 8;

	rlc->flags = RLC_LU_TYPE_FILEDISK | RLC_REGISTER_LU;
	(void) strcpy(rlc->name, argv[argc-1]);
	if ((ioctl(sbd_fd, SBD_REGISTER_LU, rlc) < 0) ||
	    (rlc->return_code != 0) || (rlc->op_ret != STMF_SUCCESS)) {
		if (rlc->return_code && (rlc->return_code < RLC_RET_MAX_VAL)) {
			(void) fprintf(stderr, "LU import failed : %s.\n",
			    rlc_ret[rlc->return_code]);
			if (rlc->return_code ==
			    RLC_RET_SIZE_NOT_SUPPORTED_BY_FS) {
				(void) fprintf(stderr, "Maximum LU size on "
				    "the underlying filesystem can be %llu "
				    "bytes.\n",
				    ((((uint64_t)1) << rlc->filesize_nbits)
				    - 1 - 64 * 1024) & 0xfffffffffffffe00ull);
			}
			if (rlc->return_code ==
			    RLC_RET_GUID_ALREADY_REGISTERED) {
				(void) fprintf(stderr, "Registered GUID is ");
				print_guid(rlc->guid, stderr);
				(void) fprintf(stderr, "\n");
			}
		} else {
			(void) fprintf(stderr, "LU import failed(%llx) : %s.\n",
			    rlc->op_ret, strerror(errno));
		}
		ret = 1;
	} else {
		if (rlc->flags & RLC_REGISTER_LU) {
			(void) printf("\nImported the following LU:\n");
			print_attr_header();
			(void) print_lu_attr(rlc->lu_handle, NULL);
			(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
			    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
			    "%02x%02x%02x%02x%02x%02x",
			    rlc->guid[0], rlc->guid[1], rlc->guid[2],
			    rlc->guid[3], rlc->guid[4], rlc->guid[5],
			    rlc->guid[6], rlc->guid[7], rlc->guid[8],
			    rlc->guid[9], rlc->guid[10], rlc->guid[11],
			    rlc->guid[12], rlc->guid[13], rlc->guid[14],
			    rlc->guid[15]);

			ret = persist_lu_register(guidAsciiBuf, argv[argc - 1]);
		}
	}

import_lu_done:;
	free(rlc);
	return (ret);
}

/*ARGSUSED*/
int
delete_lu(int argc, char *argv[], cmdOptions_t *options, void *callData)
{
	deregister_lu_cmd_t	drlc;
	int			ret = 0, i;
	char			chstr[3], *pend = NULL;
	uint32_t		ch, off = 0;
	int			exists = 0;
	char			guidAsciiBuf[33];
	nvlist_t		*nvl = NULL;

	int			stmf_ret;
	int			keep_view = 0;
	uint64_t		setToken;
	stmfGuid		inGuid;
	stmfViewEntryList	*viewEntryList;
	boolean_t		retryGetProviderData;

	for (; options->optval; options++) {
		switch (options->optval) {
		case 'k':
			keep_view = 1;
			break;
		}
	}

	if (strlen(argv[argc - 1]) != 32) {
		(void) fprintf(stderr, "GUID must be 32 characters\n");
		ret = 1;
		goto delete_lu_done;
	}

	for (i = 0; i < 32; i++) {
		guidAsciiBuf[i] = tolower(argv[argc - 1][i]);
	}

	guidAsciiBuf[i] = 0;

	do {
		retryGetProviderData = B_FALSE;
		stmf_ret = stmfGetProviderDataProt("sbd", &nvl,
		    STMF_LU_PROVIDER_TYPE, &setToken);
		if (stmf_ret != STMF_STATUS_SUCCESS) {
			(void) fprintf(stderr,
			    "Could not access persistent store\n");
			ret = 1;
			goto delete_lu_done;
		}
		ret = nvlist_remove(nvl, guidAsciiBuf, DATA_TYPE_STRING);
		if (ret == 0) {
			exists = 1;
			stmf_ret = stmfSetProviderDataProt("sbd", nvl,
			    STMF_LU_PROVIDER_TYPE, &setToken);
			if (stmf_ret != STMF_STATUS_SUCCESS) {
				if (stmf_ret == STMF_ERROR_BUSY) {
					(void) fprintf(stderr,
					    "stmf framework resource busy\n");
				} else if (stmf_ret ==
				    STMF_ERROR_PROV_DATA_STALE) {
					/*
					 * update failed, try again
					 */
					nvlist_free(nvl);
					nvl = NULL;
					retryGetProviderData = B_TRUE;
					continue;
				} else {
					(void) fprintf(stderr,
					    "unable to set persistent store "
					    "data\n");
				}
				ret = 1;
				goto delete_lu_done;
			}
		}
	} while (retryGetProviderData);

	bzero(&drlc, sizeof (drlc));
	drlc.total_struct_size = sizeof (drlc);
	drlc.flags = RLC_DEREGISTER_LU;

	chstr[2] = 0;
	i = 0;
	while ((off + 2) <= strlen(argv[argc - 1])) {
		bcopy(argv[argc -1] + off, chstr, 2);
		off += 2;

		if (!isxdigit(chstr[0]) || !isxdigit(chstr[1])) {
			(void) fprintf(stderr, "Invalid LU GUID specified.\n");
			ret = 1;
			goto delete_lu_done;
		}
		errno = 0;
		ch = strtoul(chstr, &pend, 16);
		if (errno != 0) {
			(void) fprintf(stderr, "Invalid LU GUID specified.\n");
			ret = 1;
			goto delete_lu_done;
		}
		drlc.guid[i++] = ch;

	}

	if (ioctl(sbd_fd, SBD_DEREGISTER_LU, &drlc) < 0) {
		if (errno != ENODEV) {
			(void) fprintf(stderr,
			    "Request to delete LU failed: %s\n",
			    strerror(errno));
			ret = 1;
			goto delete_lu_done;
		}
	} else if (drlc.return_code != 0) {
		(void) fprintf(stderr, "LU deregister failed: ret_code-%x",
		    drlc.return_code);
		ret = 1;
		goto delete_lu_done;
	} else {
		exists = 1;
	}

	if (!keep_view) {
		for (i = 0; i < 16; i++)
			inGuid.guid[i] = drlc.guid[i];

		if ((stmf_ret = stmfGetViewEntryList(&inGuid,
		    &viewEntryList)) == STMF_STATUS_SUCCESS) {
			for (i = 0; i < viewEntryList->cnt; i++) {
				(void) stmfRemoveViewEntry(&inGuid,
				    viewEntryList->ve[i].veIndex);
			}
		} else if (stmf_ret != STMF_ERROR_NOT_FOUND) {
			(void) fprintf(stderr,
			    "unable to remove view entries\n");
			ret = 1;
		}
	}

	if (!exists) {
		(void) fprintf(stderr, "GUID not found.\n");
		ret = 1;
		goto delete_lu_done;
	}

delete_lu_done:;
	return (ret);
}

/*ARGSUSED*/
int
modify_lu(int argc, char *argv[], cmdOptions_t *options, void *callData)
{
	modify_lu_cmd_t *mlc;
	uint32_t fl = 0, struct_size;
	int ret = 0, err;
	int i = 0;
	uint64_t size;
	int is_filename = 0;
	char chstr[3], *pend = NULL;
	uint32_t ch;
	uint32_t off = 0;

	if (argv[argc - 1][0] == '/') {
		is_filename = 1;
		fl = strlen(argv[argc - 1]) + 1;
		struct_size = sizeof (modify_lu_cmd_t) + fl - 8;
	} else {
		struct_size = sizeof (modify_lu_cmd_t);
	}
	mlc = (modify_lu_cmd_t *)malloc(struct_size);
	if (mlc == NULL) {
		(void) fprintf(stderr, "Unable to allocate memory\n");
		return (1);
	}
	bzero(mlc, sizeof (modify_lu_cmd_t));
	mlc->total_struct_size = struct_size;

	mlc->flags = RLC_LU_TYPE_FILEDISK | RLC_CREATE_LU;
	for (; options->optval; options++) {
		if (options->optval == 's') {
			err = str_to_size(options->optarg, &size);
			if (err == 1) {
				(void) fprintf(stderr,
				    "Size out of range: maximum"
				    " supported size is 9223372036854775808"
				    " (8 Exabytes)\n");
				ret = 1;
				goto modify_lu_done;
			} else if (err == 2) {
				(void) fprintf(stderr,
				    "Invalid size specified\n");
				ret = 1;
				goto modify_lu_done;
			}
			mlc->lu_size = size;
		}
	}
	if (is_filename) {
		(void) strcpy(mlc->name, argv[argc-1]);
		(void) memset(mlc->guid, 0, 16);
	} else {
		if (strlen(argv[argc - 1]) != 32) {
			(void) fprintf(stderr,
			    "Invalid device identifier or filename"
			    " specified.\nIf it is a filename, it should be an"
			    " absolute path i.e. it should start with a /\n");
			goto modify_lu_done;
		}
		chstr[2] = 0;
		i = 0;
		while ((off + 2) <= strlen(argv[argc - 1])) {
			bcopy(argv[argc -1] + off, chstr, 2);
			off += 2;

			ch = strtoul(chstr, &pend, 16);
			if (errno != 0) {
				(void) fprintf(stderr,
				    "Invalid device identifier or"
				    " filename specified.\nIf it is a"
				    " filename, it should be an absolute path"
				    " i.e. it should start with a /\n");
				ret = 1;
				goto modify_lu_done;
			}
			mlc->guid[i++] = ch;

		}
		mlc->name[0] = '\0';
	}
	if ((ioctl(sbd_fd, SBD_MODIFY_LU, mlc) < 0) ||
	    (mlc->return_code != 0) || (mlc->op_ret |= STMF_SUCCESS)) {
		if (mlc->return_code && (mlc->return_code < RLC_RET_MAX_VAL)) {
			(void) fprintf(stderr, "LU modify failed : %s.\n",
			    rlc_ret[mlc->return_code]);
			if (mlc->return_code ==
			    RLC_RET_SIZE_NOT_SUPPORTED_BY_FS) {
				(void) fprintf(stderr, "Maximum LU size on "
				    "the underlying filesystem can be %llu "
				    "bytes.\n",
				    ((((uint64_t)1) << mlc->filesize_nbits)
				    - 1) & 0xfffffffffffffe00ull);
			} else if (mlc->return_code ==
			    RLC_RET_LU_NOT_INITIALIZED) {
				(void) fprintf(stderr, "Use 'sbdadm lu-create' "
				    "to initialize the LU.\n");
			}
		} else {
			(void) fprintf(stderr, "LU modify failed(%llx) : %s.\n",
			    mlc->op_ret, strerror(errno));
		}
		ret = 1;
	} else {
		(void) printf("LU modified Successfully.\n");
	}

modify_lu_done:;
	free(mlc);
	return (ret);
}


/*ARGSUSED*/
int
list_lus(int argc, char *argv[], cmdOptions_t *options, void *callData)
{
	sbd_lu_list_t *sll;
	uint32_t i;
	ssize_t list_size;
	int retry_count = 0;
	uint32_t lu_count_in = MAX_LU_LIST;
	int ret;
	nvlist_t *nvl = NULL;
	nvpair_t *np;
	char *s;

	ret = stmfGetProviderDataProt("sbd", &nvl, STMF_LU_PROVIDER_TYPE,
	    NULL);
	if (ret != STMF_STATUS_SUCCESS) {
		if (ret == STMF_ERROR_NOT_FOUND) {
			(void) nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
		} else {
			(void) fprintf(stderr,
			    "Could not access persistent store\n");
			return (1);
		}
	}

retry_get_lu_list:
	list_size = (lu_count_in * 8) + sizeof (sbd_lu_list_t) - 8;
	sll = (sbd_lu_list_t *)calloc(1, list_size);
	if (sll == NULL) {
		(void) fprintf(stderr, "Memory allocation failure\n");
		nvlist_free(nvl);
		return (1);
	}

	sll->total_struct_size = list_size;

	sll->count_in = lu_count_in;
	if (ioctl(sbd_fd, SBD_GET_LU_LIST, sll) < 0) {
		(void) fprintf(stderr, "Unable to get LU list : %s\n",
		    strerror(errno));
		free(sll);
		nvlist_free(nvl);
		return (1);
	}
	if (sll->count_out > sll->count_in) {
		lu_count_in = sll->count_out;
		free(sll);
		if (retry_count < LU_LIST_MAX_RETRIES) {
			retry_count++;
			goto retry_get_lu_list;
		} else {
			(void) fprintf(stderr, "Unable to get LU list after %d"
			    " retries\n", retry_count);
			nvlist_free(nvl);
			return (1);
		}
	}

	(void) printf("\nFound %d LU(s)\n", sll->count_out);
	if (sll->count_out == 0)
		goto over_print_attr;

	print_attr_header();
	for (i = 0; i < sll->count_out; i++) {
		if (!print_lu_attr(sll->handles[i], &s))
			continue;
		if (nvlist_remove(nvl, s, DATA_TYPE_STRING) != 0) {
			(void) fprintf(stderr,
			    "Error: GUID %s does not exist in "
			    "persistent store\n", s);
		}
	}
over_print_attr:
	free(sll);
	np = NULL;
	while ((np = nvlist_next_nvpair(nvl, np)) != NULL) {
		if (nvpair_type(np) != DATA_TYPE_STRING)
			continue;
		if (nvpair_value_string(np, &s) != 0)
			continue;

		(void) fprintf(stderr, "%s   <Failed to load>    %s\n",
		    nvpair_name(np), s);
	}
	nvlist_free(nvl);
	return (0);
}

void
print_attr_header()
{
	(void) printf("\n");
	(void) printf("	      GUID                    DATA SIZE      "
	    "     SOURCE\n");
	(void) printf("--------------------------------  -------------------"
	    "  ----------------\n");
}

void
print_guid(uint8_t *g, FILE *f)
{
	int i;

	for (i = 0; i < 16; i++) {
		(void) fprintf(f, "%02x", g[i]);
	}
}

int
print_lu_attr(uint64_t handle, char **s)
{
	sbd_lu_attr_t *sla;

	sla = (sbd_lu_attr_t *)big_buf;

	bzero(sla, BIG_BUF_SIZE);

	sla->lu_handle = handle;
	sla->total_struct_size = BIG_BUF_SIZE;
	sla->max_name_length = BIG_BUF_SIZE - sizeof (*sla) + 7;

	if (ioctl(sbd_fd, SBD_GET_LU_ATTR, sla) < 0) {
		(void) fprintf(stderr, "Request to get LU attr failed: %s\n",
		    strerror(errno));
		return (0);
	}

	print_guid(sla->guid, stdout);

	if (sla->data_size > 9999999999999ull)
		(void) printf("  %-19llu  ", sla->data_size);
	else
		(void) printf("      %-13llu    ", sla->data_size);

	if (sla->flags & RLC_LU_TYPE_MEMDISK) {
		(void) printf("<RAM : %llu bytes>\n", sla->total_size);
	} else {
		(void) printf("%s\n", sla->name);
	}
	if (s != NULL) {
		(void) snprintf((char *)big_buf, sizeof (big_buf),
		    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
		    "%02x%02x%02x%02x%02x%02x",
		    sla->guid[0], sla->guid[1], sla->guid[2],
		    sla->guid[3], sla->guid[4], sla->guid[5],
		    sla->guid[6], sla->guid[7], sla->guid[8],
		    sla->guid[9], sla->guid[10], sla->guid[11],
		    sla->guid[12], sla->guid[13], sla->guid[14],
		    sla->guid[15]);
		*s = (char *)big_buf;
	}
	return (1);
}
