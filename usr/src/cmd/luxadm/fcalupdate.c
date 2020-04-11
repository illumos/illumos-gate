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


/*
 * I18N message number ranges
 *  This file: 4500 - 4999
 *  Shared common messages: 1 - 1999
 */

#include	<fcntl.h>
#include	<limits.h>
#include	<setjmp.h>
#include	<signal.h>
#include	<siginfo.h>
#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<strings.h>
#include	<unistd.h>
#include	<ctype.h>
#include	<dirent.h>
#include	<sys/exec.h>
#include	<sys/exechdr.h>
#include	<sys/mman.h>
#include	<sys/stat.h>
#include	<sys/types.h>
#include	<sys/fibre-channel/fcio.h>
#include	<sys/socalreg.h>
/*
 * The following define is not to
 * include sys/fc4/fcal_linkapp.h
 * file from sys/socalio.h, since it
 * has same structure defines as in
 * sys/fibre-channel/fcio.h.
 */
#define	_SYS_FC4_FCAL_LINKAPP_H
#include	<sys/socalio.h>
#include	<sys/time.h>
#include	<nl_types.h>
#include	<errno.h>
#include	<stgcom.h>
#include	<gfc.h>
#include	<l_common.h>
#include	"luxadm.h"

/*	Defines		*/
#define	FEPROM_SIZE		256*1024
#define	FEPROM_MAX_PROGRAM	25
#define	FEPROM_MAX_ERASE	1000
#define	FEPROM_READ_MEMORY	0x00
#define	FEPROM_ERASE		0x20
#define	FEPROM_ERASE_VERIFY	0xa0
#define	FEPROM_PROGRAM		0x40
#define	FEPROM_PROGRAM_VERIFY	0xc0
#define	FEPROM_RESET		0xff
#define	HBA_MAX			128

#define	FOUND			0
#define	NOT_FOUND		1
#define	PROM_SIZ		0x20010

#define	MAX_RETRIES		3
#define	MAX_WAIT_TIME		30

/*
 * The next define is to work around a problem with sbusmem driver not
 * able to round up mmap() requests that are not around page boundaries.
 */
#define	PROM_SIZ_ROUNDED	0x22000
#define	SAMPLE_SIZ		0x100

#define	REG_OFFSET		0x20000

#define	FEPROM_WWN_OFFSET	0x3fe00

#define	FEPROM_SUN_WWN		0x50200200

/*
 * We'll leave this on leadville, as the onboard
 * isn't allowed to be zapped by luxadm
 */

#define	ONBOARD_SOCAL		"SUNW,socal@d"

#define	SOCAL_STR	"SUNW,socal"
#define	SOCAL_STR_LEN	10


static uchar_t	buffer[FEPROM_SIZE];

static char	sbus_list[HBA_MAX][PATH_MAX];
static char	sbussoc_list[HBA_MAX][PATH_MAX];
static char	bootpath[PATH_MAX];
static char	version[MAXNAMELEN];

static uint_t	getsbuslist(void);
static int	load_file(char *, caddr_t, volatile socal_reg_t *);
static void	usec_delay(int);
static void	getbootdev(unsigned int);
static void	getsocpath(char *, int *);
static int	loadsocpath(const char *, int *);
static int	warn(void);
static int	findversion(int, uchar_t *);
static int	write_feprom(uchar_t *, uchar_t *, volatile socal_reg_t *);
static int	feprom_erase(volatile uchar_t *, volatile socal_reg_t *);

static struct exec exec;

int
fcal_update(unsigned int verbose, char *file)
/*ARGSUSED*/
{
int		fd, strfound = 0, retval = 0;
int		fbuf_idx, fd1, bytes_read;
caddr_t		addr;
uint_t		i;
uint_t		fflag = 0;
uint_t		vflag = 0;
uint_t		numslots;
volatile	socal_reg_t *regs;
char		*slotname, socal[MAXNAMELEN];
char		fbuf[BUFSIZ];

	if (!file)
		vflag++;
	else {
		fflag++;
		if ((fd1 = open(file, O_RDONLY)) == -1) {
			(void) fprintf(stderr,
				MSGSTR(4500,
				"Error: open() failed on file "
				"%s\n"), file);
			return (1);
		}
	/*
	 * We will just make a check to see if it the file
	 * has the "SUNW,socal" strings in it
	 * We cannot use strstr() here because we are operating on
	 * binary data and so is very likely to have embedded NULLs
	 */
		while (!strfound && ((bytes_read = read(fd1,
						fbuf, BUFSIZ)) > 0)) {
			for (fbuf_idx = 0; fbuf_idx < bytes_read;
							fbuf_idx++) {
				/* First check for the SUNW,socal string */
				if (strncmp((fbuf + fbuf_idx), SOCAL_STR,
						SOCAL_STR_LEN) == 0) {
					strfound = 1;
					break;
				}

			}
		}
		(void) close(fd1);

		if (!strfound) {
			(void) fprintf(stderr,
				MSGSTR(4501,
					"Error: %s is not a "
					"FC100/S Fcode file\n"), file);
			return (1);
		}
	}

	/*
	 * Get count of, and names of SBus slots using the SBus memory
	 * interface.
	 */
	(void) getbootdev(verbose);
	if (getenv("_LUX_D_DEBUG") != NULL) {
		(void) fprintf(stdout, "  Bootpath: %s\n", bootpath);
	}

	numslots = getsbuslist();
	(void) fprintf(stdout,
	MSGSTR(4503, "\n  Found Path to %d FC100/S Cards\n"), numslots);

	for (i = 0; i < numslots; i++) {

		/*
		 * Open SBus memory for this slot.
		 */
		slotname = &sbus_list[i][0];
		if (fflag && (strcmp(slotname, bootpath) == 0)) {
			(void) fprintf(stderr,
			MSGSTR(4504, " Ignoring %s (bootpath)\n"), slotname);
			continue;
		}

		(void) sprintf(socal, "%s:0", &sbussoc_list[i][0]);

		if ((fd = open(socal, O_RDWR)) < 0) {
			(void) sprintf(socal, "%s:1", &sbussoc_list[i][0]);
			if ((fd = open(socal, O_RDWR)) < 0) {
				(void) fprintf(stderr,
					MSGSTR(4505, "Could not open %s\n"),
					&sbussoc_list[i][0]);
				(void) fprintf(stderr,
					MSGSTR(4506, "Ignoring %s\n"),
					&sbussoc_list[i][0]);
				retval++;
				continue;
			}
		}

		(void) close(fd);

		if (verbose) {
			(void) fprintf(stdout, "\n  ");
			(void) fprintf(stdout,
			MSGSTR(85, "Opening %s\n"), slotname);
		}

		fd = open(slotname, O_RDWR);

		if (fd < 0) {
			perror(MSGSTR(4507, "open of slotname"));
			retval++;
			continue;
		}

		/*
		 * Mmap that SBus memory into my memory space.
		 */
		addr = mmap((caddr_t)0, PROM_SIZ_ROUNDED, PROT_READ|PROT_WRITE,
			MAP_SHARED, fd, 0);

		if (addr == MAP_FAILED) {
			perror(MSGSTR(46, "mmap"));
			(void) close(fd);
			retval++;
			continue;
		}

		if ((int)addr == -1) {
			perror(MSGSTR(46, "mmap"));
			(void) close(fd);
			retval++;
			continue;
		}

		regs = (socal_reg_t *)((int)addr + REG_OFFSET);

		(void) fprintf(stdout,
			MSGSTR(4508, "\n  Device: %s\n"),
			&sbussoc_list[i][0]);
		/*
		 * Load the New FCode
		 */
		if (fflag) {
			if (!warn())
				retval += load_file(file, addr, regs);
		} else if (vflag) {
			if (findversion(i, (uchar_t *)&version[0]) == FOUND) {
				(void) fprintf(stdout,
				MSGSTR(4509,
				"  Detected FC100/S Version: %s\n"), version);
			}
		}

		if (munmap(addr, PROM_SIZ) == -1) {
			perror(MSGSTR(4510, "munmap"));
			retval++;
		}

		(void) close(fd);

	}
	(void) fprintf(stdout, "  ");
	(void) fprintf(stdout, MSGSTR(125, "Complete\n"));
	return (retval);
}

static int
findversion(int index, uchar_t *version)
/*ARGSUSED*/
{
int fd, ntries;
struct socal_fm_version	*buffer;
char	socal[MAXNAMELEN];
char	fp[MAXNAMELEN];
char	prom_ver[100];
char	mcode_ver[100];
uint_t	dev_type;
fcio_t	fcio;
char	fw_rev[FC_FW_REV_SIZE + 1];


	if ((dev_type = g_get_path_type(&sbussoc_list[index][0])) == 0) {
		return (L_INVALID_PATH);
	}


	if (dev_type &  FC4_FCA_MASK) {
		P_DPRINTF("findversion: found an FC4 path\n");
		(void) sprintf(socal, "%s:0", &sbussoc_list[index][0]);
		if ((fd = open(socal, O_RDWR)) < 0) {
			(void) sprintf(socal, "%s:1", &sbussoc_list[index][0]);
			if ((fd = open(socal, O_RDWR)) < 0) {
				(void) fprintf(stderr,
					MSGSTR(4511, "Could not open %s\n"),
					&sbussoc_list[index][0]);
				(void) close(fd);
				return (NOT_FOUND);
			}
		}
		if ((buffer = (struct socal_fm_version *)malloc(
				sizeof (struct socal_fm_version))) == NULL) {
			(void) fprintf(stderr, MSGSTR(10,
				" Error: Unable to allocate memory."));
			(void) fprintf(stderr, "\n");
			(void) close(fd);
			return (NOT_FOUND);
		}

		buffer->fcode_ver = (char *)version;
		buffer->mcode_ver = mcode_ver;
		buffer->prom_ver = prom_ver;
		buffer->fcode_ver_len = MAXNAMELEN - 1;
		buffer->mcode_ver_len = 100;
		buffer->prom_ver_len = 100;

		if (ioctl(fd, FCIO_FCODE_MCODE_VERSION, buffer) < 0) {
			(void) fprintf(stderr, MSGSTR(4512,
				"fcal_s_download: could not get"
				" fcode version.\n"));
			(void) close(fd);
			(void) free(buffer);
			return (NOT_FOUND);
		}
		version[buffer->fcode_ver_len] = '\0';
		free(buffer);

	} else if (dev_type & FC_FCA_MASK) {
		/*
		 * Get the fcode and prom's fw version
		 * using new ioctls. Currently, we pass
		 * only the fcode version to the calling function
		 * and ignore the FW version (using the existing
		 * implementation). The function definition
		 * might be changed in future to pass both the
		 * fcode and FW revisions to the calling function, if
		 * needed by the calling function.
		 */
		P_DPRINTF("findversion: found an FC path\n");
		(void) sprintf(fp, "%s/fp@0,0:devctl",
			&sbussoc_list[index][0]);
		if ((fd = open(fp, O_RDWR)) < 0) {
			(void) sprintf(fp, "%s/fp@1,0:devctl",
				&sbussoc_list[index][0]);
			if ((fd = open(fp, O_RDWR)) < 0) {
				(void) fprintf(stderr,
					MSGSTR(4511, "Could not open %s\n"),
					&sbussoc_list[index][0]);
				(void) close(fd);
				return (NOT_FOUND);
			}
		}
		/* Get the fcode version */
		bzero(version, sizeof (version));
		fcio.fcio_cmd = FCIO_GET_FCODE_REV;
		/* Information read operation */
		fcio.fcio_xfer = FCIO_XFER_READ;
		fcio.fcio_obuf = (caddr_t)version;
		fcio.fcio_olen = MAXNAMELEN;

		for (ntries = 0; ntries < MAX_RETRIES; ntries++) {
			if (ioctl(fd, FCIO_CMD, &fcio) != 0) {
				if ((errno == EAGAIN) &&
					(ntries+1 < MAX_RETRIES)) {
					/* wait 30 secs */
					(void) sleep(MAX_WAIT_TIME);
					continue;
				}
				I_DPRINTF("ioctl FCIO_GET_FCODE_REV failed.\n"
					"Error: %s\n", strerror(errno));
				(void) close(fd);
				return (L_FCIO_GET_FCODE_REV_FAIL);
			}
			break;
		}
		version[MAXNAMELEN-1] = '\0';

		/* Get the FW revision */
		bzero(fw_rev, sizeof (fw_rev));
		fcio.fcio_cmd = FCIO_GET_FW_REV;
		/* Information read operation */
		fcio.fcio_xfer = FCIO_XFER_READ;
		fcio.fcio_obuf = (caddr_t)fw_rev;
		fcio.fcio_olen = FC_FW_REV_SIZE;
		for (ntries = 0; ntries < MAX_RETRIES; ntries++) {
			if (ioctl(fd, FCIO_CMD, &fcio) != 0) {
				if ((errno == EAGAIN) &&
					(ntries+1 < MAX_RETRIES)) {
					/* wait 30 secs */
					(void) sleep(MAX_WAIT_TIME);
					continue;
				}
				I_DPRINTF(" FCIO_GET_FW_REV ioctl failed.\n"
					" Error: %s\n", strerror(errno));
				(void) close(fd);
				return (L_FCIO_GET_FW_REV_FAIL);
			}
			break;
		}
	}

	(void) close(fd);
	return (FOUND);
}
/*
 * program an FEprom with data from 'source_address'.
 *	program the FEprom with zeroes,
 *	erase it,
 *	program it with the real data.
 */
static int
feprom_program(uchar_t *source_address, uchar_t *dest_address,
	volatile socal_reg_t *regs)
{
	int i;

	(void) fprintf(stdout, MSGSTR(4513, "Filling with zeroes...\n"));
	if (!write_feprom((uchar_t *)0, dest_address, regs)) {
		(void) fprintf(stderr,
			MSGSTR(4514, "FEprom at 0x%x: zero fill failed\n"),
			(int)dest_address);
		return (0);
	}

	(void) fprintf(stdout, MSGSTR(4515, "Erasing...\n"));
	for (i = 0; i < FEPROM_MAX_ERASE; i++) {
		if (feprom_erase(dest_address, regs))
			break;
	}

	if (i >= FEPROM_MAX_ERASE) {
		(void) fprintf(stderr,
			MSGSTR(4516, "FEprom at 0x%x: failed to erase\n"),
			(int)dest_address);
		return (0);
	} else if (i > 0) {
		if (i == 1) {
			(void) fprintf(stderr, MSGSTR(4517,
				"FEprom erased after %d attempt\n"), i);
		} else {
			(void) fprintf(stderr, MSGSTR(4518,
				"FEprom erased after %d attempts\n"), i);
		}
	}

	(void) fprintf(stdout, MSGSTR(4519, "Programming...\n"));
	if (!(write_feprom(source_address, dest_address, regs))) {
		(void) fprintf(stderr,
			MSGSTR(4520, "FEprom at 0x%x: write failed\n"),
			(int)dest_address);
		return (0);
	}

	/* select the zeroth bank at end so we can read it */
	regs->socal_cr.w &= ~(0x30000);
	(void) fprintf(stdout, MSGSTR(4521, "Programming done\n"));
	return (1);
}

/*
 * program an FEprom one byte at a time using hot electron injection.
 */
static int
write_feprom(uchar_t *source_address, uchar_t *dest_address,
	volatile socal_reg_t *regs)
{
	int pulse, i;
	uchar_t *s = source_address;
	volatile uchar_t *d;

	for (i = 0; i < FEPROM_SIZE; i++, s++) {

		if ((i & 0xffff) == 0) {
			(void) fprintf(stdout,
			MSGSTR(4522, "selecting bank %d\n"), i>>16);
			regs->socal_cr.w &= ~(0x30000);
			regs->socal_cr.w |= i & 0x30000;
		}

		d = dest_address + (i & 0xffff);

		for (pulse = 0; pulse < FEPROM_MAX_PROGRAM; pulse++) {
			*d = FEPROM_PROGRAM;
			*d = source_address ? *s : 0;
			usec_delay(50);
			*d = FEPROM_PROGRAM_VERIFY;
			usec_delay(30);
			if (*d == (source_address ? *s : 0))
					break;
		}

		if (pulse >= FEPROM_MAX_PROGRAM) {
			*dest_address = FEPROM_RESET;
			return (0);
		}
	}

	*dest_address = FEPROM_RESET;
	return (1);
}

/*
 * erase an FEprom using Fowler-Nordheim tunneling.
 */
static int
feprom_erase(volatile uchar_t *dest_address, volatile socal_reg_t *regs)
{
	int i;
	volatile uchar_t *d = dest_address;

	*d = FEPROM_ERASE;
	usec_delay(50);
	*d = FEPROM_ERASE;

	usec_delay(10000); /* wait 10ms while FEprom erases */

	for (i = 0; i < FEPROM_SIZE; i++) {

		if ((i & 0xffff) == 0) {
			regs->socal_cr.w &= ~(0x30000);
			regs->socal_cr.w |= i & 0x30000;
		}

		d = dest_address + (i & 0xffff);

		*d = FEPROM_ERASE_VERIFY;
		usec_delay(50);
		if (*d != 0xff) {
			*dest_address = FEPROM_RESET;
			return (0);
		}
	}
	*dest_address = FEPROM_RESET;
	return (1);
}

static void
usec_delay(int s)
{
	hrtime_t now, then;

	now = gethrtime();
	then = now + s*1000;
	do {
		now = gethrtime();
	} while (now < then);
}

static uint_t
getsbuslist(void)
{
	int devcnt = 0;
	char devpath[PATH_MAX];

	/* We're searching the /devices directory, so... */
	(void) strcpy(devpath, "/devices");

	/* get the directory entries under /devices for socal sbusmem */
	(void) getsocpath(devpath, (int *)&devcnt);

	return (devcnt);
}

static void
getbootdev(unsigned int verbose)
{
	char *df = "df /";
	FILE *ptr;
	char *p, *p1;
	char bootdev[PATH_MAX];
	char buf[BUFSIZ];
	int foundroot = 0;


	if ((ptr = popen(df, "r")) != NULL) {
		while (fgets(buf, BUFSIZ, ptr) != NULL) {
			if (p = strstr(buf, "/dev/dsk/")) {
				(void) memset((char *)&bootdev[0], 0,
					PATH_MAX);
				p1 = p;
				while (*p1 != '\0') {
					if (!isalnum(*p1) && (*p1 != '/'))
						*p1 = ' ';
					p1++;
				}
				(void) sscanf(p, "%s", bootdev);
				foundroot = 1;
			}
		}
		if (!foundroot) {
			if (verbose)
				(void) fprintf(stderr, MSGSTR(44,
					"root is not on a local disk!\n"));
			(void) memset((char *)&bootpath[0], 0, PATH_MAX);
			return;
		}
		(void) pclose(ptr);
		if (bootdev[0]) {
			char *ls;
			char *p1;
			char *p2 = NULL;
			char *sbusmem = "/sbusmem@";
			char *slot = ",0:slot";

			ls = (char *)malloc(PATH_MAX);
			(void) memset((char *)ls, 0, PATH_MAX);
			(void) strcpy(ls, "ls -l ");
			(void) strcat(ls, bootdev);
			if ((ptr = popen(ls, "r")) != NULL) {
				while (fgets(buf, BUFSIZ, ptr) != NULL) {
					if (p = strstr(buf, "/devices")) {
					    if (p1 = strstr(buf, "sbus")) {
						while (*p1 != '/')
							p1++;
						p2 = strstr(p1, "@");
						++p2;
						*p1 = '\0';
					    } else {
						if (p1 = strstr(buf,
								SOCAL_STR)) {
							p2 = strstr(p1, "@");
							++p2;
							--p1;
							*p1 = '\0';
						}
					    }
					}
				}
				(void) pclose(ptr);
			}
			(void) memset((char *)&bootdev[0], 0, PATH_MAX);
			(void) sscanf(p, "%s", bootdev);
			(void) memset((char *)&bootpath[0], 0, PATH_MAX);
			(void) strcat(bootpath, bootdev);
			(void) strcat(bootpath, sbusmem);
			if (p2) {
				(void) strncat(bootpath, p2, 1);
				(void) strcat(bootpath, slot);
				(void) strncat(bootpath, p2, 1);
			}
		}
	}
}

/*
 * This function reads "size" bytes from the FC100/S PROM.
 * source_address: PROM address
 * dest_address:   local memeory
 * offset:         Location in PROM to start reading from.
 */
static void
feprom_read(uchar_t *source_address, uchar_t *dest_address,
		int offset, int size, volatile socal_reg_t *regs)
{
uchar_t  *s = source_address;
uchar_t  *d = dest_address;
int	i = offset;

	if (getenv("_LUX_D_DEBUG") != NULL) {
		(void) fprintf(stdout,
			"  feprom_read: selecting bank %d\n",
			(i&0xf0000)>>16);
		if (size <= 8) {
			(void) fprintf(stdout, "  Data read: ");
		}
	}
	regs->socal_cr.w = i & 0xf0000;
	s = source_address + (i & 0xffff);
	*s = FEPROM_READ_MEMORY;
	usec_delay(6);
	for (; s < source_address + (i & 0xffff) + size; d++, s++) {
		*d = *s;
		if ((getenv("_LUX_D_DEBUG") != NULL) &&
			(size <= 8)) {
			(void) fprintf(stdout, "0x%x ", *d);
		}
	}
	if ((getenv("_LUX_D_DEBUG") != NULL) &&
		(size <= 8)) {
		(void) fprintf(stdout, "\n  From offset: 0x%x\n",
			offset);
	}
}


static int
load_file(char *file, caddr_t prom, volatile socal_reg_t *regs)
{
uint_t	wwn_d8, wwn_lo;
uint_t	wwn_hi;
int ffd = open(file, 0);

	wwn_hi = FEPROM_SUN_WWN;

	if (ffd < 0) {
		perror(MSGSTR(4524, "open of file"));
		exit(1);
	}
	(void) fprintf(stdout, MSGSTR(4525, "Loading FCode: %s\n"), file);

	if (read(ffd, &exec, sizeof (exec)) != sizeof (exec)) {
		perror(MSGSTR(4526, "read exec"));
		exit(1);
	}

	if (exec.a_trsize || exec.a_drsize) {
		(void) fprintf(stderr,
			MSGSTR(4527, "%s: is relocatable\n"), file);
		exit(1);
	}

	if (exec.a_data || exec.a_bss) {
		(void) fprintf(stderr,
			MSGSTR(4528, "%s: has data or bss\n"), file);
		exit(1);
	}

	if (exec.a_machtype != M_SPARC) {
		(void) fprintf(stderr,
			MSGSTR(4529, "%s: not for SPARC\n"), file);
		exit(1);
	}

	(void) fprintf(stdout, MSGSTR(4530,
		"Loading 0x%x bytes from %s at offset 0x%x\n"),
		(int)exec.a_text, file, 0);

	if (read(ffd, &buffer, exec.a_text) != exec.a_text) {
		perror(MSGSTR(4531, "read"));
		exit(1);
	}

	(void) close(ffd);

	feprom_read((uchar_t *)prom, (uchar_t *)&wwn_d8,
		FEPROM_WWN_OFFSET, 4, regs);
	feprom_read((uchar_t *)prom, (uchar_t *)&wwn_lo,
		FEPROM_WWN_OFFSET + 4, 4, regs);
	wwn_hi |= wwn_d8 & 0x0f; /* only last digit is interesting */
	if (getenv("_LUX_D_DEBUG") != NULL) {
		(void) fprintf(stdout,
			"  load_file: Writing WWN hi:0x%x lo:0x%x "
			"to the FC100/S PROM\n", wwn_hi, wwn_lo);
	}
	/* put wwn into buffer location */
	bcopy((const void *)&wwn_hi,
		(void *)&buffer[FEPROM_WWN_OFFSET],
		sizeof (wwn_hi));
	bcopy((const void *)&wwn_lo,
		(void *)&buffer[FEPROM_WWN_OFFSET + 4],
		sizeof (wwn_lo));
	bcopy((const void *)&wwn_hi,
		(void *)&buffer[FEPROM_WWN_OFFSET + 8],
		sizeof (wwn_hi));
	bcopy((const void *)&wwn_lo,
		(void *)&buffer[FEPROM_WWN_OFFSET + 0xc],
		sizeof (wwn_lo));

	if (feprom_program((uchar_t *)buffer, (uchar_t *)prom, regs) == 0) {
		/* here 0 means failure */
		return (1);
	}

	return (0);
}

static int
warn(void)
{
	char input[1024];

	input[0] = '\0';

	(void) fprintf(stderr, MSGSTR(4532,
"\nWARNING!! This program will update the FCode in this FC100/S Sbus Card.\n"));
	(void) fprintf(stderr,  MSGSTR(4533,
"This may take a few (5) minutes. Please be patient.\n"));

loop1:
	(void) fprintf(stderr, MSGSTR(4534,
		"Do you wish to continue ? (y/n) "));

	(void) gets(input);

	if ((strcmp(input, MSGSTR(4535, "y")) == 0) ||
			(strcmp(input, MSGSTR(40, "yes")) == 0)) {
		return (FOUND);
	} else if ((strcmp(input, MSGSTR(4536, "n")) == 0) ||
			(strcmp(input, MSGSTR(45, "no")) == 0)) {
		(void) fprintf(stderr, MSGSTR(4537, "Not Downloading FCode\n"));
		return (NOT_FOUND);
	} else {
		(void) fprintf(stderr, MSGSTR(4538, "Invalid input\n"));
		goto loop1;
	}
}


/*
 * getsocpath():
 *	Searches the /devices directory recursively returning all soc_name
 *	entries in sbussoc_list (global). This excludes port entries and
 *	onboard socal (which leaves only directory entries with
 *	soc_name included). devcnt is updated to reflect number of soc_name
 *	devices found.
 */

static void
getsocpath(char *devpath, int *devcnt)
{
	struct stat	statbuf;
	struct dirent	*dirp;
	DIR		*dp;
	char		*ptr;

	if (lstat(devpath, &statbuf) < 0) {
		(void) fprintf(stderr,
		MSGSTR(4539, "Error: %s lstat() error\n"), devpath);
		exit(1);
	}

	if (S_ISDIR(statbuf.st_mode) == 0)
		/*
		 * not a directory so
		 * we don't care about it - return
		 */
		return;

	else {
		if (strstr(devpath, ONBOARD_SOCAL))
			return;

		if (strstr(devpath, SOCAL_STR)) {
			/* It's a keeper - call the load function */
			if ((loadsocpath(devpath, devcnt)) < 0) {
				(void) fprintf(stderr,
				MSGSTR(4540, "Error: Cannot set device list\n"),
					devpath);
				exit(1);
			}
			/*
			 * if socal directory - return,
			 * nothing else to see here
			 */
			return;
		}
	}

	/*
	 * It's a directory. Call ourself to
	 * traverse the path(s)
	 */

	ptr = devpath + strlen(devpath);
	*ptr++ = '/';
	*ptr = 0;

	/* Forget the /devices/pseudo/ directory */
	if (strcmp(devpath, "/devices/pseudo/") == 0)
		return;

	if ((dp = opendir(devpath)) == NULL) {
		(void) fprintf(stderr,
		MSGSTR(4541, "Error: %s Can't read directory\n"), devpath);
		exit(1);
	}

	while ((dirp = readdir(dp)) != NULL) {

		if (strcmp(dirp->d_name, ".") == 0 ||
			strcmp(dirp->d_name, "..") == 0)
			continue;

		(void) strcpy(ptr, dirp->d_name); /* append name */
		getsocpath(devpath, devcnt);
	}

	if (closedir(dp) < 0) {
		(void) fprintf(stderr,
		MSGSTR(4542, "Error: %s Can't close directory\n"), devpath);
		exit(1);
	}
}

static int
loadsocpath(const char *pathname, int *devcnt)
{
	int ret = 0;
	int len;
	int len_tmp;
	char *sp;
	char *sp_tmp;
	char buffer[PATH_MAX];


	/*
	 * Okay we found a device, now let's load it in to sbussoc_list
	 * and load the sbusmem file into sbus_list
	 */

	if (pathname != NULL && *devcnt < HBA_MAX) {
		(void) strcpy(sbussoc_list[*devcnt], pathname);
		if (sp_tmp = strstr(sbussoc_list[*devcnt], SOCAL_STR)) {
			sp = sp_tmp;
			/* len_tmp will be len of "SUNW,socal@" */
			len_tmp = SOCAL_STR_LEN + 1;
		}
		len = strlen(sbussoc_list[*devcnt]) - strlen(sp);
		(void) strncpy(buffer, sbussoc_list[*devcnt], len);
		buffer[len] = '\0';
		sp += len_tmp;
		(void) sprintf(sbus_list[*devcnt], "%ssbusmem@%c,0:slot%c",
			buffer, sp[0], sp[0]);
		*devcnt += 1;
	}
	else
		ret = -1;
	return (ret);
}
