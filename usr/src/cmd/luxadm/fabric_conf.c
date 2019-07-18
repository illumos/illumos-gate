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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <libdevice.h>
#include <sys/fibre-channel/fcio.h>
#include "common.h"

static int parse_line(char *line, char *path, char *wwn, char *filename);
static int create_ap_instance(char *ap_id, char *wwn_string,
	char *filename, char *line);
static void log_error(char *msg_id, char *input_tmplt, ...);
static char ctoi(char c);

/*
 *  Simple wrapper for syslog error messages.
 *  Allows easy addition of syserr output if desired.
 */
static void
log_error(char *msg_id, char *input_tmplt, ...)
{
	va_list ap;
	char input_merged_msg[200];
	char *msg_template = "ID[luxadm.create_fabric_device.%s] %s";
	/*
	 * First %s for msg_id in merged msg.
	 * Second %s is for  input merged_msg
	 */
	char *merged_msg;

	va_start(ap, input_tmplt);
	/* insert caller's args */
	(void) vsprintf(input_merged_msg, input_tmplt, ap);
	va_end(ap);

	merged_msg = (char *)malloc(strlen(msg_template) +
	    strlen(input_merged_msg) +
	    strlen(msg_id) + 1);
	if (merged_msg == NULL) {
		syslog(LOG_ERR, "ID[luxadm.create_fabric_device.2317] "
		    "malloc failure, %s", strerror(errno));
	} else {
		sprintf(merged_msg, msg_template, msg_id, input_merged_msg);
			/* first insert msg_id */
		syslog(LOG_ERR, merged_msg, "");
		(void) puts(merged_msg);	/* also print message */
		free(merged_msg);
	}
}

/*
 *   Routines for reading tapestry repository file
 */

#define	COMMENT_CHAR '#'
int
read_repos_file(char *repos_filename)
{
	int fd;
	char *line;
	char *tmp_ptr, *mmap_ptr;
	char path[MAXPATHLEN];
	int ret;
	char wwn[FC_WWN_SIZE*2+1];
	struct stat stbuf;
	unsigned int filesize;
	unsigned int bytes_read;

	if (repos_filename == NULL || *repos_filename == '\0') {
		log_error("2310",
		    "filename missing for -f option of "
		    "luxadm -e create_fabric_device");
		return (-1);
	}

	fd = open(repos_filename, O_RDONLY);

	if (fd == -1) {
		log_error("2311",
		    "fopen failed: cannot open repository file %s. %d",
		    repos_filename, strerror(errno));
		return (-1);
	}

	if (fstat(fd, &stbuf) == -1) {
		close(fd);
		log_error("2312", "stat failed on file %s. %s",
		    repos_filename, strerror(errno));
		return (-1);
	}
	filesize = stbuf.st_size;
	tmp_ptr = mmap_ptr = mmap((caddr_t)0, filesize,
	    (PROT_READ | PROT_WRITE), MAP_PRIVATE, fd, 0);

	if (mmap_ptr == MAP_FAILED) {
		log_error("2315", "Failed to mmap file %s. %s",
		    repos_filename, strerror(errno));
		return (-1);
	}

	bytes_read = 0;
	while (bytes_read < filesize) {
		line = tmp_ptr;
		while (bytes_read < filesize && *tmp_ptr != '\n') {
			bytes_read++;
			tmp_ptr++;
		}
		if (*tmp_ptr == '\n') {
			*tmp_ptr = '\0';
			tmp_ptr++;
			bytes_read++;
		}

		/* If the line is a comment, read another line */
		if (*line == COMMENT_CHAR) {
			continue;
		}
		ret = parse_line(line, path, wwn, repos_filename);
		if (ret == 0) {
			ret = create_ap_instance(path,
			    wwn, repos_filename, line);
		}
	}

	ret = close(fd);
	ret = munmap(mmap_ptr, filesize);
	return (ret);
}

/*
 * Input is paramater 1 - a line from repository
 * Output is other parameters, the path to the attachment point,
 * and the port wwn are parsed from the repository
 * Format is
 *	"/devices/pci..../fp@1,0:fc::wwn"
 * If controller name is missing, that's okay.  Other fields
 * must be present
 *
 * Return 0 on success or -1 on failure; all failures logged to syslog.
 */
#define	WWN_DELIM "::"
static int
parse_line(char *line, char *path, char *wwn, char *filename)
{
	char *p_path, *p_wwn, *p_delim;
	char *line_copy;

	line_copy = strdup(line);
	if (line_copy == NULL) {
		log_error("2317", "malloc failure, %s", strerror(errno));
	}
	p_path = line_copy;
	p_delim = strstr(p_path, WWN_DELIM);
	if (p_delim == NULL) {
		log_error("2313",
		    "Invalid line (%s) in file %s.", line, filename);
		free(line_copy);
		return (-1);
	}
	*p_delim = '\0';	/* NULL terminate path */

	if (strlcpy(path, p_path, MAXPATHLEN) >= MAXPATHLEN) {
		log_error("2318",
		    "Path too long (%s) in file %s.", p_path, filename);
		free(line_copy);
		return (-1);
	}

	p_wwn = p_delim + strlen(WWN_DELIM);
	/*
	 * Now look for the blank delimiter before the controller
	 *
	 * This is just the case when there may be a controller #
	 * after the attachment point and WWN. For example -
	 * /devices/pci@b,2000/pci@2/SUNW,qlc@4/fp@0,0:fc::220000203707f4f1 c4
	 */
	p_delim = strchr(p_wwn, ' ');
	if (p_delim != NULL) {
		/* now p_delim points to blank */
		*p_delim = '\0';	/* terminate wwn at delim */
	} else {
		char *p_last_char;
		p_last_char = p_wwn+strlen(p_wwn)-1;
		if (*p_last_char == '\n') {
			*p_last_char = '\0';
		}
	}
	strcpy(wwn, p_wwn);
	free(line_copy);
	return (0);
}

static char
ctoi(char c)
{
	if ((c >= '0') && (c <= '9'))
		c -= '0';
	else if ((c >= 'A') && (c <= 'F'))
		c = c - 'A' + 10;
	else if ((c >= 'a') && (c <= 'f'))
		c = c - 'a' + 10;
	else
		c = -1;
	return (c);
}

/*
 * "string" is Input and "port_wwn" has the output
 *
 * This function converts a string to WWN.
 * For example a string like
 * "220000203707F4F1" gets converted to 0x220000203707F4F1 ...
 * where
 * port_wwn[0] = 0x22,
 * port_wwn[1] = 0x00,
 * port_wwn[2] = 0x00,
 * port_wwn[3] = 0x20,
 * port_wwn[4] = 0x37,
 * port_wwn[5] = 0x07,
 * port_wwn[6] = 0xF4, and
 * port_wwn[7] = 0xF1
 */
static int
string_to_wwn(const uchar_t *string, uchar_t *port_wwn)
{
	int	i;
	char	c, c1;
	uchar_t	*wwnp;

	wwnp = port_wwn;
	for (i = 0; i < WWN_SIZE; i++, wwnp++) {

		c = ctoi(*string++);
		c1 = ctoi(*string++);
		if (c == -1 || c1 == -1)
			return (-1);
		*wwnp = ((c << 4) + c1);
	}

	return (0);
}

static int
create_ap_instance(char *ap_id, char *wwn_string,
    char *filename, char *line)
{
	devctl_hdl_t bus_handle, dev_handle;
	devctl_ddef_t ddef_handle;
	int ret;
	uchar_t wwn_array[FC_WWN_SIZE];

	ddef_handle = devctl_ddef_alloc("dummy", 0);
	if (ddef_handle == NULL) {
		log_error("2314",
		    "Internal error to process line (%s) in file: %s. %s",
		    line, filename, strerror(errno));
		return (-1);
	}
	/*
	 * g_string_to_wwn() has not been used here because it
	 * prepends 2 NULLs.
	 */
	if (string_to_wwn((uchar_t *)wwn_string, wwn_array) != 0) {
		log_error("2314",
		    "Internal error to process line (%s) in file: %s. %s",
		    line, filename, strerror(errno));
		devctl_ddef_free(ddef_handle);
		return (-1);
	}
	(void) devctl_ddef_byte_array(ddef_handle,
	    "port-wwn", FC_WWN_SIZE, wwn_array);

	if ((bus_handle = devctl_bus_acquire(ap_id, 0)) == NULL) {
		devctl_ddef_free(ddef_handle);
		log_error("2314",
		    "Internal error to process line (%s) in file: %s. %s",
		    line, filename, strerror(errno));
		return (-1);
	}
	if (ret =
	    devctl_bus_dev_create(bus_handle, ddef_handle, 0, &dev_handle)) {
		devctl_ddef_free(ddef_handle);
		devctl_release(bus_handle);
		log_error("2316",
		    "configuration failed for line (%s) in file: %s. %s",
		    line, filename, strerror(errno));
		return (-1);
	}
	devctl_release(dev_handle);
	devctl_ddef_free(ddef_handle);
	devctl_release(bus_handle);
	return (ret);
}
