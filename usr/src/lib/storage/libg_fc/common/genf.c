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




/*LINTLIBRARY*/

/*
 *	This module is part of the Fibre Channel Interface library.
 *
 */

/*
 * I18N message number ranges
 *  This file: 10500 - 10999
 *  Shared common messages: 1 - 1999
 */

/*	Includes	*/
#include	<stdlib.h>
#include 	<stdio.h>
#include	<sys/file.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<fcntl.h>
#include	<string.h>
#include	<errno.h>
#include	<assert.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<sys/param.h>
#include	<sys/dklabel.h>
#include	<sys/autoconf.h>
#include	<sys/utsname.h>
#include 	<sys/ddi.h>		/* for min */
#include	<ctype.h>		/* for isprint */
#include	<sys/scsi/scsi.h>
#include	<dirent.h>		/* for DIR */
#include	<nl_types.h>
#include	<locale.h>
#include	<thread.h>
#include	<synch.h>
#include	<l_common.h>
#include	<stgcom.h>
#include	<l_error.h>
#include	<g_state.h>
#include	<libdevinfo.h>


/*	Defines		*/
#define	BYTES_PER_LINE		16	/* # of bytes to dump per line */
#define	SCMD_UNKNOWN		0xff

/* Bus strings - for internal use by g_get_path_type() only */
#define	PCI_BUS			1
#define	SBUS			2

struct str_type {
	char *string;
	uint_t type;
};

static struct str_type ValidBusStrings[] = {
	{"pci@", PCI_BUS},
	{"sbus@", SBUS},
	{NULL, 0}
};


/*
 *	Strings below were used before cougar driver(qlc) was proposed.
 *	{"scsi/", FC_PCI_FCA},
 *	{"fibre-channel/", FC_PCI_FCA},
 */
static struct str_type ValidFCAstrings[] = {
	{"SUNW,ifp@", FC4_PCI_FCA | FC4_IFP_XPORT},
	{"SUNW,socal@", FC4_SOCAL_FCA},
	{NULL, 0}
};

static struct str_type ValidXportStrings[] = {
	{"/sf@", FC4_SF_XPORT},
	{"/fp@", FC_GEN_XPORT},
	{NULL, 0}
};

struct _enclDisk {
	char *vid;
	char *pid;
};

/*
 * SENA/SUNWGS type enclosure disk table. This table contains vendor IDs and
 * the non-unique portion of the product identifier sufficient for
 * comparison. This table needs to be updated as new drives are supported
 * in the SENA/SUNWGS type enclosures that do not have a corresponding match
 * in this table. Currently, the v880 and v890 are the only shipping products
 * that utilize the SUNWGS type enclosure. SENA is EOL'd. The risk of new
 * devices being added that do not match an entry in this table is small but it
 * does exist.
 */
static struct _enclDisk enclDiskTbl[] = {
	{"SUN", "SENA"},
	{"SUN", "SUNWGS"},
	{"FUJITSU", "MA"},
	{"HITACHI", "DK"},
	{"HITACHI", "HU"},
	{"SEAGATE", "ST"},
	{NULL, NULL}
};


/* i18n */
nl_catd		l_catd;


/*	Internal Functions	*/
static	void	string_dump(char *, uchar_t *, int, int, char msg_string[]);

/*
 * Allocate space for and return a pointer to a string
 * on the stack.  If the string is null, create
 * an empty string.
 * Use g_destroy_data() to free when no longer used.
 */
char *
g_alloc_string(char *s)
{
	char	*ns;

	if (s == (char *)NULL) {
		ns = (char *)g_zalloc(1);
	} else {
		ns = (char *)g_zalloc(strlen(s) + 1);
		if (ns != NULL) {
			(void) strncpy(ns, s, (strlen(s) + 1));
		}
	}
	return (ns);
}


/*
 * This routine is a wrapper for free.
 */
void
g_destroy_data(void *data)
{
	A_DPRINTF("  g_destroy_data: Free\'ed buffer at 0x%x\n",
		data);
	free((void *)data);
}


/*
 * Dump a structure in hexadecimal.
 */
void
g_dump(char *hdr, uchar_t *src, int nbytes, int format)
{
	int i;
	int n;
	char	*p;
	char	s[256];

	assert(format == HEX_ONLY || format == HEX_ASCII);

	(void) strcpy(s, hdr);
	for (p = s; *p; p++) {
		*p = ' ';
	}

	p = hdr;
	while (nbytes > 0) {
		(void) fprintf(stdout, "%s", p);
		p = s;
		n = min(nbytes, BYTES_PER_LINE);
		for (i = 0; i < n; i++) {
			(void) fprintf(stdout, "%02x ", src[i] & 0xff);
		}
		if (format == HEX_ASCII) {
			for (i = BYTES_PER_LINE-n; i > 0; i--) {
				(void) fprintf(stdout, "   ");
			}
			(void) fprintf(stdout, "    ");
			for (i = 0; i < n; i++) {
				(void) fprintf(stdout, "%c",
					isprint(src[i]) ? src[i] : '.');
			}
		}
		(void) fprintf(stdout, "\n");
		nbytes -= n;
		src += n;
	}
}

/*
 * Internal routine to clean up ../'s in paths.
 * returns 0 if no "../" are left.
 *
 * Wouldn't it be nice if there was a standard system library
 * routine to do this...?
 */
static int
cleanup_dotdot_path(char *path)
{
	char holder[MAXPATHLEN];
	char *dotdot;
	char *previous_slash;

	/* Find the first "/../" in the string */
	dotdot = strstr(path, "/../");
	if (dotdot == NULL) {
		return (0);
	}


	/*
	 * If the [0] character is '/' and "../" immediatly
	 * follows it, then we can strip the ../
	 *
	 *	/../../foo/bar == /foo/bar
	 *
	 */
	if (dotdot == path) {
		strcpy(holder, &path[3]); /* strip "/.." */
		strcpy(path, holder);
		return (1);
	}

	/*
	 * Now look for the LAST "/" before the "/../"
	 * as this is the parent dir we can get rid of.
	 * We do this by temporarily truncating the string
	 * at the '/' just before "../" using the dotdot pointer.
	 */
	*dotdot = '\0';
	previous_slash = strrchr(path, '/');
	if (previous_slash == NULL) {
		/*
		 * hmm, somethings wrong.  path looks something
		 * like "foo/../bar/" so we can't really deal with it.
		 */
		return (0);
	}
	/*
	 * Now truncate the path just after the previous '/'
	 * and slam everything after the "../" back on
	 */
	*(previous_slash+1) = '\0';
	strcat(path, dotdot+4);
	return (1); /* We may have more "../"s */
}


/*
 * Follow symbolic links from the logical device name to
 * the /devfs physical device name.  To be complete, we
 * handle the case of multiple links.  This function
 * either returns NULL (no links, or some other error),
 * or the physical device name, alloc'ed on the heap.
 *
 * NOTE: If the path is relative, it will be forced into
 * an absolute path by pre-pending the pwd to it.
 */
char *
g_get_physical_name_from_link(char *path)
{
	struct stat	stbuf;
	char		source[MAXPATHLEN];
	char		scratch[MAXPATHLEN];
	char		pwd[MAXPATHLEN];
	char		*tmp;
	int			cnt;

	/* return NULL if path is NULL */
	if (path == NULL) {
		return (NULL);
	}

	strcpy(source, path);
	for (;;) {

		/*
		 * First make sure the path is absolute.  If not, make it.
		 * If it's already an absolute path, we have no need
		 * to determine the cwd, so the program should still
		 * function within security-by-obscurity directories.
		 */
		if (source[0] != '/') {
			tmp = getcwd(pwd, MAXPATHLEN);
			if (tmp == NULL) {
				O_DPRINTF("getcwd() failed - %s\n",
					strerror(errno));
				return (NULL);
			}
			/*
			 * Handle special case of "./foo/bar"
			 */
			if (source[0] == '.' && source[1] == '/') {
				strcpy(scratch, source+2);
			} else { /* no "./" so just take everything */
				strcpy(scratch, source);
			}
			strcpy(source, pwd);
			strcat(source, "/");
			strcat(source, scratch);
		}

		/*
		 * Clean up any "../"s that are in the path
		 */
		while (cleanup_dotdot_path(source));

		/*
		 * source is now an absolute path to the link we're
		 * concerned with
		 *
		 * See if there's a real file out there.  If not,
		 * we have a dangling link and we ignore it.
		 */

		if (stat(source, &stbuf) == -1) {
			O_DPRINTF("stat() failed for %s- %s\n",
				source, strerror(errno));
			return (NULL);
		}
		if (lstat(source, &stbuf) == -1) {
			O_DPRINTF("lstat() failed for - %s\n",
				source, strerror(errno));
			return (NULL);
		}
		/*
		 * If the file is not a link, we're done one
		 * way or the other.  If there were links,
		 * return the full pathname of the resulting
		 * file.
		 *
		 * Note:  All of our temp's are on the stack,
		 * so we have to copy the final result to the heap.
		 */
		if (!S_ISLNK(stbuf.st_mode)) {
			return (g_alloc_string(source));
		}
		cnt = readlink(source, scratch, sizeof (scratch));
		if (cnt < 0) {
			O_DPRINTF("readlink() failed - %s\n",
				strerror(errno));
			return (NULL);
		}
		/*
		 * scratch is on the heap, and for some reason readlink
		 * doesn't always terminate things properly so we have
		 * to make certain we're properly terminated
		 */
		scratch[cnt] = '\0';

		/*
		 * Now check to see if the link is relative.  If so,
		 * then we have to append it to the directory
		 * which the source was in. (This is non trivial)
		 */
		if (scratch[0] != '/') {
			tmp = strrchr(source, '/');
			if (tmp == NULL) { /* Whoa!  Something's hosed! */
				O_DPRINTF("Internal error... corrupt path.\n");
				return (NULL);
			}
			/* Now strip off just the directory path */
			*(tmp+1) = '\0'; /* Keeping the last '/' */
			/* and append the new link */
			strcat(source, scratch);
			/*
			 * Note:  At this point, source should have "../"s
			 * but we'll clean it up in the next pass through
			 * the loop.
			 */
		} else {
			/* It's an absolute link so no worries */
			strcpy(source, scratch);
		}
	}
	/* Never reach here */
}

/*
 * Function for getting physical pathnames
 *
 * This function can handle 3 different inputs.
 *
 * 1) Inputs of the form cN
 *	This requires the program  to search the /dev/rdsk
 *	directory for a device that is conected to the
 *	controller with number 'N' and then getting
 *	the physical pathname of the controller.
 *	The format of the controller pathname is
 *	/devices/.../.../SUNW,soc@x,x/SUNW,pln@xxxx,xxxxxxxx:ctlr
 *	The physical pathname is returned.
 *
 * 2) Inputs of the form /dev/rdsk/cNtNdNsN
 *	These are identified by being a link
 *	The physical path they are linked to is returned.
 *
 * 3) Inputs of the form /devices/...
 *	These are actual physical names.
 *	They are not converted.
 */
char *
g_get_physical_name(char *path)
{
	struct stat	stbuf;
	char		s[MAXPATHLEN];
	char		namebuf[MAXPATHLEN];
	char		savedir[MAXPATHLEN];
	char		*result = NULL;
	DIR		*dirp;
	struct dirent	*entp;
	char		*dev_name, *char_ptr;
	struct stat	sb;
	int		found_flag = 0;
	int		status = 0;
	int		i;

	/* return invalid path if path NULL */
	if (path == NULL) {
		return (NULL);
	}

	(void) strcpy(s, path);
	/*
	 * See if the form is cN
	 * Must handle scenaro where there is a file cN in this directory
	 * Bug ID: 1184633
	 *
	 * We could be in the /dev/rdsk directory and the file could be of
	 * the form cNdNsN (See man disks).
	 */
	status = stat(s, &stbuf);
	if (((status == -1) && (errno == ENOENT)) ||
	    ((s[0] == 'c') && ((int)strlen(s) > 1) && ((int)strlen(s) < 5))) {
		/*
		 * Further qualify cN entry
		 */
		if ((s[0] != 'c') || ((int)strlen(s) <= 1) ||
		((int)strlen(s) >= 5)) {
			goto exit;
		}
		for (i = 1; i < (int)strlen(s); i++) {
			if ((s[i] < '0') || (s[i] > '9')) {
				goto exit;
			}
		}
		/*
		 * path does not point to a file or file is of form cN
		 */
		P_DPRINTF("  g_get_physical_name: "
			"Found entry of the form cN n=%s len=%d\n",
			&s[1], strlen(s));

		dev_name = g_zalloc(sizeof ("/dev/rdsk"));
		sprintf((char *)dev_name, "/dev/rdsk");

		if ((dirp = opendir(dev_name)) == NULL) {
			g_destroy_data(dev_name);
			goto exit;
		}

		while ((entp = readdir(dirp)) != NULL) {
		    if (strcmp(entp->d_name, ".") == 0 ||
			strcmp(entp->d_name, "..") == 0)
			continue;

		    if (entp->d_name[0] != 'c')
			/*
			 * Silently Ignore for now any names
			 * not stating with c
			 */
			continue;

		    sprintf(namebuf, "%s/%s", dev_name, entp->d_name);

		    if ((lstat(namebuf, &sb)) < 0) {
				L_WARNINGS(MSGSTR(55,
					"Warning: Cannot stat %s\n"),
					namebuf);
			continue;
		    }

		    if (!S_ISLNK(sb.st_mode)) {
				L_WARNINGS(MSGSTR(56,
					"Warning: %s is not a symbolic link\n"),
					namebuf);
			continue;
		    }

		    if (strstr(entp->d_name, s) != NULL) {
			/*
			 * found link to device in /devices
			 *
			 * Further qualify to be sure I have
			 * not found entry of the form c10
			 * when I am searching for c1
			 */
			if (atoi(&s[1]) == atoi(&entp->d_name[1])) {
			    P_DPRINTF("  g_get_physical_name: "
			    "Found entry in /dev/rdsk matching %s: %s\n",
				s, entp->d_name);
				found_flag = 1;
				break;
			}
		    }
		}
		closedir(dirp);
		g_destroy_data(dev_name);

		if (found_flag) {
		    result = g_get_physical_name_from_link(namebuf);
		    if (result == NULL) {
			goto exit;
		    }
			/*
			 * Convert from device name to controller name
			 */
		    char_ptr = strrchr(result, '/');
		    *char_ptr = '\0';   /* Terminate sting  */
		    (void) strcat(result, CTLR_POSTFIX);
		}
		goto exit;
	}
	if (status == -1)
		goto exit;

	if (lstat(s, &stbuf) == -1) {
			L_WARNINGS(MSGSTR(134,
				"%s: lstat() failed - %s\n"),
				s, strerror(errno));
		goto exit;
	}
	/*
	 */
	if (!S_ISLNK(stbuf.st_mode)) {
		/*
		 * Path is not a linked file so must be
		 * a physical path
		 */
		if (S_ISCHR(stbuf.st_mode) || S_ISDIR(stbuf.st_mode)) {
			/* Make sure a full path as that is required. */
			if (strstr(s, "/devices")) {
				result = g_alloc_string(s);
			} else {
				if (getcwd(savedir,
					sizeof (savedir)) == NULL) {
					return (NULL);
				}
				/*
				 * Check for this format:
				 * ./ssd@0,1:g,raw
				 */
				if (s[0] == '.') {
					strcat(savedir, &s[1]);
				} else {
					strcat(savedir, "/");
					strcat(savedir, s);
				}
				result = g_alloc_string(savedir);
			}
		}
	} else {
		/*
		 * Entry is linked file
		 * so follow link to physical name
		 */
		result = g_get_physical_name_from_link(path);
	}

exit:
	return (result);
}

/*
 *	Function to open a device
 */
int
g_object_open(char *path, int flag)
{
int fd = -1, retry = 0;
	if (getenv("_LUX_O_DEBUG") != NULL) {
		(void) printf("  Object_open:%s ", path);
		if (flag & O_WRONLY) {
			(void) printf("O_WRONLY,");
		} else if (flag & O_RDWR) {
			(void) printf("O_RDWR,");
		} else {
			(void) printf("O_RDONLY,");
		}
		if (flag & O_NDELAY) {
			(void) printf("O_NDELAY,");
		}
		if (flag & O_APPEND) {
			(void) printf("O_APPEND,");
		}
		if (flag & O_DSYNC) {
			(void) printf("O_DSYNC,");
		}
		if (flag & O_RSYNC) {
			(void) printf("O_RSYNC,");
		}
		if (flag & O_SYNC) {
			(void) printf("O_SYNC,");
		}
		if (flag & O_NOCTTY) {
			(void) printf("O_NOCTTY,");
		}
		if (flag & O_CREAT) {
			(void) printf("O_CREAT,");
		}
		if (flag & O_EXCL) {
			(void) printf("O_EXCL,");
		}
		if (flag & O_TRUNC) {
			(void) printf("O_TRUNC,");
		}
		(void) printf("\n");
	}

	/* Open retries introduced due to bugid 4473337	*/
	errno	= 0;
	fd	= open(path, flag);
	while (fd < 0 && retry++ < RETRY_OBJECT_OPEN && (
			errno == EBUSY || errno == EAGAIN)) {
		O_DPRINTF("  Object_open: Retried:%d %d %s\n",
			retry, errno, path);
		(void) usleep(WAIT_OBJECT_OPEN);
		fd = open(path, flag);
	}
	if (fd < 0) {
		O_DPRINTF("  Object_open: Open failed:%s\n", path);
	}
	return (fd);
}


/*
 * Return a pointer to a string telling us the name of the command.
 */
char *
g_scsi_find_command_name(int cmd)
{
/*
 * Names of commands.  Must have SCMD_UNKNOWN at end of list.
 */
struct scsi_command_name {
	int command;
	char	*name;
} scsi_command_names[29];

register struct scsi_command_name *c;

	scsi_command_names[0].command = SCMD_TEST_UNIT_READY;
	scsi_command_names[0].name = MSGSTR(61, "Test Unit Ready");

	scsi_command_names[1].command = SCMD_FORMAT;
	scsi_command_names[1].name = MSGSTR(110, "Format");

	scsi_command_names[2].command = SCMD_REASSIGN_BLOCK;
	scsi_command_names[2].name = MSGSTR(77, "Reassign Block");

	scsi_command_names[3].command = SCMD_READ;
	scsi_command_names[3].name = MSGSTR(27, "Read");

	scsi_command_names[4].command = SCMD_WRITE;
	scsi_command_names[4].name = MSGSTR(54, "Write");

	scsi_command_names[5].command = SCMD_READ_G1;
	scsi_command_names[5].name = MSGSTR(79, "Read(10 Byte)");

	scsi_command_names[6].command = SCMD_WRITE_G1;
	scsi_command_names[6].name = MSGSTR(51, "Write(10 Byte)");

	scsi_command_names[7].command = SCMD_MODE_SELECT;
	scsi_command_names[7].name = MSGSTR(97, "Mode Select");

	scsi_command_names[8].command = SCMD_MODE_SENSE;
	scsi_command_names[8].name = MSGSTR(95, "Mode Sense");

	scsi_command_names[9].command = SCMD_REASSIGN_BLOCK;
	scsi_command_names[9].name = MSGSTR(77, "Reassign Block");

	scsi_command_names[10].command = SCMD_REQUEST_SENSE;
	scsi_command_names[10].name = MSGSTR(74, "Request Sense");

	scsi_command_names[11].command = SCMD_READ_DEFECT_LIST;
	scsi_command_names[11].name = MSGSTR(80, "Read Defect List");

	scsi_command_names[12].command = SCMD_INQUIRY;
	scsi_command_names[12].name = MSGSTR(102, "Inquiry");

	scsi_command_names[13].command = SCMD_WRITE_BUFFER;
	scsi_command_names[13].name = MSGSTR(53, "Write Buffer");

	scsi_command_names[14].command = SCMD_READ_BUFFER;
	scsi_command_names[14].name = MSGSTR(82, "Read Buffer");

	scsi_command_names[15].command = SCMD_START_STOP;
	scsi_command_names[15].name = MSGSTR(67, "Start/Stop");

	scsi_command_names[16].command = SCMD_RESERVE;
	scsi_command_names[16].name = MSGSTR(72, "Reserve");

	scsi_command_names[17].command = SCMD_RELEASE;
	scsi_command_names[17].name = MSGSTR(75, "Release");

	scsi_command_names[18].command = SCMD_MODE_SENSE_G1;
	scsi_command_names[18].name = MSGSTR(94, "Mode Sense(10 Byte)");

	scsi_command_names[19].command = SCMD_MODE_SELECT_G1;
	scsi_command_names[19].name = MSGSTR(96, "Mode Select(10 Byte)");

	scsi_command_names[20].command = SCMD_READ_CAPACITY;
	scsi_command_names[20].name = MSGSTR(81, "Read Capacity");

	scsi_command_names[21].command = SCMD_SYNC_CACHE;
	scsi_command_names[21].name = MSGSTR(64, "Synchronize Cache");

	scsi_command_names[22].command = SCMD_READ_DEFECT_LIST;
	scsi_command_names[22].name = MSGSTR(80, "Read Defect List");

	scsi_command_names[23].command = SCMD_GDIAG;
	scsi_command_names[23].name = MSGSTR(108, "Get Diagnostic");

	scsi_command_names[24].command = SCMD_SDIAG;
	scsi_command_names[24].name = MSGSTR(69, "Set Diagnostic");

	scsi_command_names[25].command = SCMD_PERS_RESERV_IN;
	scsi_command_names[25].name = MSGSTR(10500, "Persistent Reserve In");

	scsi_command_names[26].command = SCMD_PERS_RESERV_OUT;
	scsi_command_names[26].name = MSGSTR(10501, "Persistent Reserve out");

	scsi_command_names[27].command = SCMD_LOG_SENSE;
	scsi_command_names[27].name = MSGSTR(10502, "Log Sense");

	scsi_command_names[28].command = SCMD_UNKNOWN;
	scsi_command_names[28].name = MSGSTR(25, "Unknown");


	for (c = scsi_command_names; c->command != SCMD_UNKNOWN; c++)
		if (c->command == cmd)
			break;
	return (c->name);
}


/*
 *	Function to create error message containing
 *	scsi request sense information
 */

void
g_scsi_printerr(struct uscsi_cmd *ucmd, struct scsi_extended_sense *rq,
		int rqlen, char msg_string[], char *err_string)
{
	int		blkno;

	switch (rq->es_key) {
	case KEY_NO_SENSE:
		(void) sprintf(msg_string, MSGSTR(91, "No sense error"));
		break;
	case KEY_RECOVERABLE_ERROR:
		(void) sprintf(msg_string, MSGSTR(76, "Recoverable error"));
		break;
	case KEY_NOT_READY:
		(void) sprintf(msg_string,
			MSGSTR(10503,
			"Device Not ready."
			" Error: Random Retry Failed: %s\n."),
			err_string);
		break;
	case KEY_MEDIUM_ERROR:
		(void) sprintf(msg_string, MSGSTR(99, "Medium error"));
		break;
	case KEY_HARDWARE_ERROR:
		(void) sprintf(msg_string, MSGSTR(106, "Hardware error"));
		break;
	case KEY_ILLEGAL_REQUEST:
		(void) sprintf(msg_string, MSGSTR(103, "Illegal request"));
		break;
	case KEY_UNIT_ATTENTION:
		(void) sprintf(msg_string,
			MSGSTR(10504,
			"Unit attention."
			"Error: Random Retry Failed.\n"));
		break;
	case KEY_WRITE_PROTECT:
		(void) sprintf(msg_string, MSGSTR(52, "Write protect error"));
		break;
	case KEY_BLANK_CHECK:
		(void) sprintf(msg_string, MSGSTR(131, "Blank check error"));
		break;
	case KEY_VENDOR_UNIQUE:
		(void) sprintf(msg_string, MSGSTR(58, "Vendor unique error"));
		break;
	case KEY_COPY_ABORTED:
		(void) sprintf(msg_string, MSGSTR(123, "Copy aborted error"));
		break;
	case KEY_ABORTED_COMMAND:
		(void) sprintf(msg_string,
			MSGSTR(10505,
			"Aborted command."
			" Error: Random Retry Failed.\n"));
		break;
	case KEY_EQUAL:
		(void) sprintf(msg_string, MSGSTR(117, "Equal error"));
		break;
	case KEY_VOLUME_OVERFLOW:
		(void) sprintf(msg_string, MSGSTR(57, "Volume overflow"));
		break;
	case KEY_MISCOMPARE:
		(void) sprintf(msg_string, MSGSTR(98, "Miscompare error"));
		break;
	case KEY_RESERVED:
		(void) sprintf(msg_string, MSGSTR(10506,
			"Reserved value found"));
		break;
	default:
		(void) sprintf(msg_string, MSGSTR(59, "Unknown error"));
		break;
	}

	(void) sprintf(&msg_string[strlen(msg_string)],
		MSGSTR(10507, " during: %s"),
		g_scsi_find_command_name(ucmd->uscsi_cdb[0]));

	if (rq->es_valid) {
		blkno = (rq->es_info_1 << 24) | (rq->es_info_2 << 16) |
			(rq->es_info_3 << 8) | rq->es_info_4;
		(void) sprintf(&msg_string[strlen(msg_string)],
			MSGSTR(49, ": block %d (0x%x)"), blkno, blkno);
	}

	(void) sprintf(&msg_string[strlen(msg_string)], "\n");

	if (rq->es_add_len >= 6) {
		(void) sprintf(&msg_string[strlen(msg_string)],
		MSGSTR(132, "  Additional sense: 0x%x   ASC Qualifier: 0x%x\n"),
			rq->es_add_code, rq->es_qual_code);
			/*
			 * rq->es_add_info[ADD_SENSE_CODE],
			 * rq->es_add_info[ADD_SENSE_QUAL_CODE]);
			 */
	}
	if (rq->es_key == KEY_ILLEGAL_REQUEST) {
		string_dump(MSGSTR(47, " cmd:   "), (uchar_t *)ucmd,
			sizeof (struct uscsi_cmd), HEX_ONLY, msg_string);
		string_dump(MSGSTR(48, " cdb:   "),
			(uchar_t *)ucmd->uscsi_cdb,
			ucmd->uscsi_cdblen, HEX_ONLY, msg_string);
	}
	string_dump(MSGSTR(43, " sense:  "),
		(uchar_t *)rq, 8 + rq->es_add_len, HEX_ONLY,
		msg_string);
	rqlen = rqlen;	/* not used */
}


/*
 *		Special string dump for error message
 */
static	void
string_dump(char *hdr, uchar_t *src, int nbytes, int format, char msg_string[])
{
	int i;
	int n;
	char	*p;
	char	s[256];

	assert(format == HEX_ONLY || format == HEX_ASCII);

	(void) strcpy(s, hdr);
	for (p = s; *p; p++) {
		*p = ' ';
	}

	p = hdr;
	while (nbytes > 0) {
		(void) sprintf(&msg_string[strlen(msg_string)],
			"%s", p);
		p = s;
		n = min(nbytes, BYTES_PER_LINE);
		for (i = 0; i < n; i++) {
			(void) sprintf(&msg_string[strlen(msg_string)],
				"%02x ",
				src[i] & 0xff);
		}
		if (format == HEX_ASCII) {
			for (i = BYTES_PER_LINE-n; i > 0; i--) {
				(void) sprintf(&msg_string[strlen(msg_string)],
					"   ");
			}
			(void) sprintf(&msg_string[strlen(msg_string)],
				"    ");
			for (i = 0; i < n; i++) {
				(void) sprintf(&msg_string[strlen(msg_string)],
					"%c",
					isprint(src[i]) ? src[i] : '.');
			}
		}
		(void) sprintf(&msg_string[strlen(msg_string)], "\n");
		nbytes -= n;
		src += n;
	}
}



/*
 * This routine is a wrapper for malloc.  It allocates pre-zeroed space,
 * and checks the return value so the caller doesn't have to.
 */
void *
g_zalloc(int count)
{
	void	*ptr;

	ptr = (void *) calloc(1, (unsigned)count);
	A_DPRINTF("  g_zalloc: Allocated 0x%x bytes "
			"at 0x%x\n", count, ptr);

	return (ptr);
}

/*
 * Open up the i18n catalog.
 * Returns:
 *  0 = O.K.
 * -1 = Failed (Will revert to default strings)
 */
int
g_i18n_catopen(void)
{
	static int fileopen = 0;
	static mutex_t mp;

	if (setlocale(LC_ALL, "") == NULL) {
	    (void) fprintf(stderr,
		"Cannot operate in the locale requested. "
		"Continuing in the default C locale\n");
	}
	if (mutex_lock(&mp) != 0) {
		return (-1);
	}
	if (!fileopen) {
		l_catd = catopen("a5k_g_fc_i18n_cat", NL_CAT_LOCALE);
		if (l_catd == (nl_catd)-1) {
			(void) mutex_unlock(&mp);
			return (-1);
		}
		fileopen = 1;
	}
	(void) mutex_unlock(&mp);
	return (0);
}

/* Macro used by g_get_path_type() */
#define	GetMatch(s_ptr)	\
	for (found = 0, search_arr_ptr = s_ptr; \
		search_arr_ptr->string != NULL; \
			search_arr_ptr++) {\
		if (strstr(path_ptr, search_arr_ptr->string) != NULL) {\
			found = 1;\
			break;\
		}\
	}

/*
 * Input  : A NULL terminated string
 *          This string is checked to be an absolute device path
 * Output :
 * 	The FCA type and Xport type if found in the path on success
 *	0 on Failure
 *
 * Examples of valid device strings :
 *
 * Non Fabric FC driver :
 * /devices/io-unit@f,e0200000/sbi@0,0/SUNW,socal@1,0/sf@1,0:ctlr
 * /devices/io-unit@f,e2200000/sbi@0,0/SUNW,socal@3,0/sf@0,0/ssd@20,0:c,raw
 * /devices/sbus@1f,0/SUNW,socal@0,0/sf@0,0:devctl
 * /devices/sbus@1f,0/SUNW,socal@2,0/sf@1,0/ssd@w2200002037110cbf,0:b,raw
 * /devices/pci@1f,4000/SUNW,ifp@4:devctl
 * /devices/pci@1f,4000/SUNW,ifp@2/ssd@w2100002037049ba0,0:c,raw
 * /devices/pci@6,4000/pci@2/SUNW,ifp@5/ssd@w210000203708b44f,0:c,raw
 *
 * Fabric FC driver (fp) :
 * 	- offical device path for Qlogic 2202 with proper FCODE
 *	  as of 12/99.
 * /devices/pci@1f,2000/pci@1/SUNW,qlc@5/fp@0,0:devctl
 * /devices/pci@e,2000/pci@2/SUNW,qlc@4/fp@0,0:devctl
 *
 */
uint_t
g_get_path_type(char *path)
{
	uint_t path_type = 0;
	int	i = 0, pathcnt = 1;
	char *path_ptr = path;
	struct str_type *search_arr_ptr; /* updated by GetMatch macro */
	char found;			 /* Updated by GetMatch marco */
	char		drvr_path1[MAXPATHLEN];
	mp_pathlist_t	pathlist;
	int		p_on = 0, p_st = 0;

	/* Path passed must be an absolute device path */
	if (strncmp(path_ptr, DEV_PREFIX, DEV_PREFIX_LEN) ||
				(strlen(path_ptr) == DEV_PREFIX_LEN)) {
		return (0);	/* Invalid path */
	}

	/* if mpxio device, need to convert from vhci to phci */
	if (strstr(path, SCSI_VHCI)) {
		(void) strcpy(drvr_path1, path);
		if (g_get_pathlist(drvr_path1, &pathlist)) {
			return (0);
		}
		pathcnt = pathlist.path_count;
		p_on = p_st = 0;
		for (i = 0; i < pathcnt; i++) {
			if (pathlist.path_info[i].path_state < MAXPATHSTATE) {
				if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_ONLINE) {
					p_on = i;
					break;
				} else if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_STANDBY) {
					p_st = i;
				}
			}
		}
		if (pathlist.path_info[p_on].path_state ==
		    MDI_PATHINFO_STATE_ONLINE) {
			/* on_line path */
			(void) strcpy(drvr_path1,
				pathlist.path_info[p_on].path_hba);
		} else {
			/* standby or path0 */
			(void) strcpy(drvr_path1,
				pathlist.path_info[p_st].path_hba);
		}
		free(pathlist.path_info);
		path_ptr = drvr_path1;
	}

	GetMatch(ValidBusStrings);
	if (found == 0) {
		/* No valid bus string - so not a valid path */
		return (0);
	}

	GetMatch(ValidFCAstrings);	/* Check for a valid FCA string */
	if (found != 0) {
		path_type |= search_arr_ptr->type;
	}

	/*
	 * continue to check xport even without valid FCA string.
	 * This is to support 3rd party FCA vendor on Leadville stack.
	 */
	GetMatch(ValidXportStrings);	/* Check for a valid transport str */
	if (found == 0) {
		return (path_type);
	} else {
		/*
		 * if leadville tranport is detected and fca is not set yet,
		 * set fca flag to generic FC_FCA_MASK.
		 */
		if ((search_arr_ptr->type == FC_GEN_XPORT) &&
			(!(path_type & FC_FCA_MASK))) {
			path_type |= FC_FCA_MASK;
		}
	}
	path_type |= search_arr_ptr->type;

	/*
	 * A quick sanity check to make sure that we dont have
	 * a combination that is not possible
	 */
	if (((path_type & (FC4_FCA_MASK | FC_XPORT_MASK)) ==
			path_type) ||
		((path_type & (FC_FCA_MASK | FC4_XPORT_MASK)) ==
			path_type)) {
		path_type = 0;
	}

	return (path_type);
}


/*
 * g_get_port_path(char *, portlist_t *)
 * Purpose: Find all port nexus paths for a particular driver
 * Input:   portdrvr
 *		set to name of driver for which to find the paths
 * Output:  portlist
 *		allocated structure to hold paths found
 *		user must call g_free_portlist(portlist_t *) to
 *		free allocated memory
 */
int
g_get_port_path(char *portdrvr, portlist_t *portlist)
{
	di_node_t root;
	di_node_t node;
	di_minor_t minor_node;
	char hbapathfound[MAXPATHLEN];
	char *tmppath;
	struct stat buf;

	/* return invalid argument if *portdrvr or *portlist is NULL */
	if ((portdrvr == NULL) || (portlist == NULL)) {
		return (L_INVALID_ARG);
	}

	/* Create a snapshot of the kernel device tree */
	root = di_init("/", DINFOCPYALL);
	if (root == DI_NODE_NIL) {
		return (L_DEV_SNAPSHOT_FAILED);
	}

	/* point to first node which matches portdrvr */
	node = di_drv_first_node(portdrvr, root);
	if (node == DI_NODE_NIL) {
		/*
		 * Could not find driver node
		 */
		(void) di_fini(root);
		if (errno == EINVAL)
			return (L_PORT_DRIVER_NOT_FOUND);
		else
			return (L_PHYS_PATH_NOT_FOUND);
	}

	while (node) {
		/* point to first minor node which matches node */
		minor_node = di_minor_next(node, DI_MINOR_NIL);

		/* if we have a minor node use it */
		while (minor_node) {
			/*
			 * Is this a devctl or pseudo node?
			 * If not, skip it.
			 * Soc+ HBA port device paths such as:
			 * 	/devices/sbus@2,0/SUNW,socal@d,10000:0
			 * are pseudo nodes as of S9 so we need to
			 * include those as well.
			 */
			if (di_minor_nodetype(minor_node) &&
				(strcmp(di_minor_nodetype(minor_node),
					DDI_NT_NEXUS) &&
				strcmp(di_minor_nodetype(minor_node),
					DDI_PSEUDO))) {
				minor_node = di_minor_next(node, minor_node);
				continue;
			}
			/*
			 * Prepend '/devices' to path
			 * Note: The path returned from di_devfs_path
			 * does NOT begin with '/devices'.
			 * '/devices' is considered a mount point
			 */
			strcpy(hbapathfound, "/devices");
			tmppath = di_devfs_path(node);
			strcat(hbapathfound, tmppath);
			(void) free(tmppath);
			strcat(hbapathfound, ":");
			strcat(hbapathfound, di_minor_name(minor_node));
			/*
			 * Verify that the path is validly constructed
			 */
			if ((stat(hbapathfound, (struct stat *)&buf)) < 0) {
				(void) di_fini(root);
				return (L_STAT_ERROR);
			}
			/* allocate memory and copy constructed path */
			if ((portlist->hbacnt > MAX_HBA_PORT - 1) ||
			    ((portlist->physpath[portlist->hbacnt] =
				(char *)malloc(MAXPATHLEN)) == NULL)) {
				(void) di_fini(root);
				return (L_MALLOC_FAILED);
			}
			strcpy(portlist->physpath[portlist->hbacnt],
				hbapathfound);
			portlist->hbacnt++;
			minor_node = di_minor_next(node, minor_node);
		}
		node = di_drv_next_node(node);
	}
	/*
	 * Destroy the snapshot and return
	 */
	(void) di_fini(root);
	return (0);
}

/*
 * Free the allocated portlist structure
 */
void
g_free_portlist(portlist_t *portlist)
{
	int x = 0;

	/* return if portlist is NULL */
	if (portlist == NULL) {
		return;
	}

	for (x = 0; x < portlist->hbacnt; x++) {
		if (portlist->physpath[x] != NULL) {
			free(portlist->physpath[x]);
		}
	}
}

/*
 * Check VID/PID against enclosure disk table
 */
boolean_t
g_enclDiskChk(char *vid, char *pid)
{
	int i;
	for (i = 0; enclDiskTbl[i].vid; i++) {
		if ((strncmp(vid, enclDiskTbl[i].vid,
		    strlen(enclDiskTbl[i].vid)) == 0) &&
		    (strncmp(pid, enclDiskTbl[i].pid,
		    strlen(enclDiskTbl[i].pid)) == 0)) {
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}
