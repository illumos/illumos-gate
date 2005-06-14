/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <devid.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <meta.h>
#include <libsvm.h>
#include <svm.h>

/*
 * magic strings in system
 */
#define	BEGMDDBSTR	"* Begin MDD database info (do not edit)\n"
#define	ENDMDDBSTR	"* End MDD database info (do not edit)\n"
#define	NEW_BEGMDDBSTR	"# Begin MDD database info (do not edit)\n"
#define	NEW_ENDMDDBSTR	"# End MDD database info (do not edit)\n"

#define	MDDBBOOTLIST	"mddb_bootlist"

#define	SYS_COMMENTCHAR	'*'
#define	CONF_COMMENTCHAR '#'

typedef struct {
	char *prop_name;
	int  prop_val;
} md_prop_t;

typedef enum {
	MDDB_SYS_FILE,
	MDDB_MDCONF_FILE
} ftype_t;

static md_prop_t upgrade_props[] = {
		{ PROP_KEEP_REPL_STATE, 0 },
		{ PROP_DEVID_DESTROY, 0},
		{ NULL, 0}
};

/*
 * The following functions manage upgrade properties
 */

void
set_upgrade_prop(char *prop_name, int val)
{
	md_prop_t *upp;

	upp = &upgrade_props[0];

	for (; upp->prop_name != NULL; upp++) {
		if (strcmp(upp->prop_name, prop_name) == 0) {
			upp->prop_val = val;
			return;
		}
	}
}

int
is_upgrade_prop(char *prop_name)
{
	md_prop_t *upp;

	upp = &upgrade_props[0];

	for (; upp->prop_name != NULL; upp++) {
		if (strcmp(upp->prop_name, prop_name) == 0) {
			return (upp->prop_val == 1);
		}
	}
	return (0);
}

int
create_in_file_prop(char *prop_name, char *fname)
{
	FILE *fp;
	md_prop_t *upp;
	int rval = RET_ERROR;

	if ((fp = fopen(fname, "a")) == NULL) {
		return (errno);
	}

	upp = &upgrade_props[0];

	for (; upp->prop_name != NULL; upp++) {
		if (strcmp(upp->prop_name, prop_name) == 0) {
			(void) fprintf(fp, "%s = 1;\n", upp->prop_name);
			rval = RET_SUCCESS;
			break;
		}
	}
	(void) fclose(fp);
	return (rval);
}

static int
is_devid_added(char *str)
{
	int cnt = 0;
	char *cp;

	/* there are exactly 3 colons in the string for devid */
	for (cnt = 0; cnt < 4; cnt++) {
		if ((cp = strchr(str, ':')) == NULL)
			break;
		str = ++cp;
	}
	return (cnt == 3);
}

/*
 * FUNCTION: parse_bootlist
 *	Parse the bootlist and add the extra field to mddb_boolist entry to
 *	conform to devid changes.
 *
 * Old format: <drivername>:<minor_number>:<offset>
 * New format: <drivername>:<minor_number>:<offset>:<devid>
 * Devid of id0 implies no device id.
 *
 * INPUT: *line - contains the mddb_bootlist
 *	  *tfp - File pointer to the md.conf.tmp file.
 *
 * RETURN:
 *	  0	- Success
 *	  > 0	- Failure. Errno returned
 */

static int
parse_bootlist(char *line, FILE *tfp)
{
	char output[1024];
	char *cp;
	int retval = RET_SUCCESS;

	(void) memset(output, 0, sizeof (output));

	if (line[0] == SYS_COMMENTCHAR) {
		output[0] = CONF_COMMENTCHAR;
	}
	/* move the line start of mddbbootlist */
	cp = strstr(line, MDDBBOOTLIST);
	if (cp != NULL)
		line = cp;

	/* grab the "mddb_boolist" word */
	cp = strtok(line, "= ");
	(void) strcat(output, cp);
	(void) strcat(output, "=\042"); /* add back the EQUAL and QUOTE chars */

	/*
	 * The line passed in is for example,
	 * mddb_bootlist1="sd:7:16:id1,sd@SIBM_DDRS34560SUN4.2G2N9688_____/h";
	 * At this point mddb_bootlist and "=" have been parsed out.
	 * The remaining string consists of driver name, colon separator and
	 * the device id(if it exists) within quotes.
	 * The deviceid string can contain upper and lower letters, digits
	 * and +-.=_~. Quotes, spaces and \n and \t are not
	 * allowed. They are converted to either _ or their ascii value.
	 * So using space,\n,;and quotes as a separator is safe.
	 */

	while ((cp = strtok(NULL, " \n\042;")) != NULL) {
		(void) strcat(output, cp);
		if (!is_devid_added(cp)) {
			/* append :id0 for devid */
			(void) strcat(strcat(output, ":"),
						devid_str_encode(NULL, NULL));

			/* no devid => SDS->SLVM migration. Set the flag */
			set_upgrade_prop(PROP_DEVID_DESTROY, 1);
		}
		(void) strcat(output, " "); /* leave space between entries */
	}

	/* remove the extra space at the end */
	output[strlen(output) - 1] = 0;
	(void) strcat(output, "\042;\n");
	if (fprintf(tfp, "%s", output) < 0) {
		retval = errno;
	}
	return (retval);
}

/*
 * FUNCTION: snarf_n_modify_bootlist
 *  This function stuffs the mddb_bootlist from either etc/system
 * or kernel/drv/md.conf of the target system into a temporary file tname.
 * The boolist in the temporary file is in device ID format.
 *
 * INPUT: *fp - file pointer that contains the mddb_bootlist.
 *	  *tname - file into which the modified bootlist will be written to.
 *	  * buf - buffer handed by upper level routine for reading in contents.
 *	  * bufsiz - size of the buffer.
 *	  mddb_file - flag
 *
 * RETURN:
 *	0	- Success
 *	> 0	- Failure. Errno returned.
 */

static int
snarf_n_modify_bootlist(
	FILE *fp,	/* File pointer to snarf from */
	char *tname,	/* name of the temporary file */
	char *buf,	/* Buffer to read into */
	int bufsz,	/* buffer size */
	ftype_t mddb_file /* flag to indicate if its /etc/system or md.conf */
)
{
	FILE *tfp;
	int rval = RET_SUCCESS;
	char *fname = SYSTEM_FILE;
	char *mddb_start = BEGMDDBSTR;
	char *mddb_end = ENDMDDBSTR;
	convflag_t cstatus = MD_STR_NOTFOUND;

	if (mddb_file == MDDB_MDCONF_FILE) {
		fname = MD_CONF;
		mddb_start = NEW_BEGMDDBSTR;
		mddb_end = NEW_ENDMDDBSTR;
	}

	if ((tfp = fopen(tname, "a")) == NULL)
		return (errno);
	debug_printf("Convert from %s\n", fname);

	rewind(fp);
	while (fgets(buf, bufsz, fp) != NULL) {
		if (strcmp(buf, mddb_start) == 0) {
			cstatus = MD_STR_START;
			if (fprintf(tfp, "%s", NEW_BEGMDDBSTR) < 0) {
				rval = errno;
				break;
			}
			continue;
		}
		if (cstatus == MD_STR_START) {
			if (strcmp(buf, mddb_end) == 0) {
				cstatus = MD_STR_DONE;
				if (fprintf(tfp, "%s", NEW_ENDMDDBSTR) < 0) {
					rval = errno;
					break;
				}

				if (mddb_file == MDDB_MDCONF_FILE)
					continue;
				else
					break;
			}

			rval = parse_bootlist(buf, tfp);
			if (rval == RET_SUCCESS)
				continue;
			else
				break;
		}
		if (mddb_file == MDDB_MDCONF_FILE) {
			if (fprintf(tfp, "%s\n", buf) < 0) {
				rval = errno;
				break;
			}
		}

	} /* while (fgets */

	if (cstatus == MD_STR_NOTFOUND || cstatus == MD_STR_START)
		rval = RET_ERROR;
	(void) fclose(tfp);
	return (rval);
}


/*
 * FUNCTION: convert_bootlist
 * Get the bootlist from $ROOT/etc/system and add modified bootlist to
 * md.conf.
 * The function converts the mddb_boolist format from that in /etc/system
 * to md.conf. Also new fields are added to handle the devid id format.
 * A copy of md.conf is created and the new entries are added to it.
 * The name of the new file is returned to the calling program.
 *
 * Input: system file name
 *	  md.conf file name
 *	  pointer to  temp file name.
 * RETURN:
 *	 *tname - name of the file that has md.conf + new mddb_boolist entries
 *	 0	- success
 *	 -1	- mddb_bootlist not found
 *	 > 0	- errno
 *
 */

int
convert_bootlist(
	char 	*sname, /* system file name */
	char	*mdconf, /* md.conf file name */
	char 	**tname /* temp file name */
)
{
	FILE	*fp;
	char	cmd_buf[MDDB_BOOTLIST_MAX_LEN];
	int	retval = RET_SUCCESS;

	/* check names */
	assert(sname != NULL);
	assert(tname != NULL);

	/* get temp name */
	*tname = tmpnam(NULL);

	if ((fp = fopen(sname, "r")) == NULL) {
		retval = errno;
		goto out;
	}
	if (valid_bootlist(fp, MDDB_BOOTLIST_MAX_LEN) == RET_SUCCESS) {
		if ((retval = copyfile(mdconf, *tname)) == RET_ERROR) {
			debug_printf("convert_bootlist: copy %s %s failed\n",
				mdconf, *tname);
			goto out;
		}
		retval = snarf_n_modify_bootlist(fp, *tname, cmd_buf,
				MDDB_BOOTLIST_MAX_LEN, MDDB_SYS_FILE);
	} else {
		(void) fclose(fp); /* close system file */
		if ((fp = fopen(mdconf, "r")) == NULL) {
			retval = errno;
			goto out;
		}
		if (valid_bootlist(fp, MDDB_BOOTLIST_MAX_LEN) == RET_ERROR) {
			retval = RET_ERROR;
			goto out;
		}
		retval = snarf_n_modify_bootlist(fp, *tname, cmd_buf,
			MDDB_BOOTLIST_MAX_LEN, MDDB_MDCONF_FILE);
	}
out:
	debug_printf("convert_bootlist: retval %d\n", retval);
	if (fp != NULL)
		(void) fclose(fp);

	if ((retval != RET_SUCCESS) && (*tname != NULL)) {
		(void) unlink(*tname);
		free(*tname);
	}
	return (retval);
}
