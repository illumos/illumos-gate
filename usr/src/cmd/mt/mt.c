/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mt -- magnetic tape manipulation program
 */
#include <stdio.h>
#include <ctype.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/mtio.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/buf.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/scsi/targets/stdef.h>
#include <fcntl.h>


#define	equal(s1, s2)	(strcmp(s1, s2) == 0)
#define	MTASF		100	/* absolute file positioning; first file is 0 */

/*
 * This can't be DEFTAPE in mtio.h because that is currently the rewinding
 * unit which makes 'mt fsf' a questionable activity at best.
 */
#define	DEFAULT_NRW_TAPE	"/dev/rmt/0n"

static int print_config(int mtfd);
static char *print_key(short key_code);
static void printreg(char *, ushort_t, char *);
static int status(int mtfd, struct mtget *);

/* Pseudo flag for open even if drive is not ready (Unloaded) or reserved */
#define	O_UNLOAD (O_RDWR | O_NDELAY)

static const struct commands {
	char *c_name;
	int c_code;
	int c_oflag;
	int c_usecnt;
} com[] = {
	{ "weof",		MTWEOF,			O_RDWR,		1 },
	{ "eof",		MTWEOF,			O_RDWR,		1 },
	{ "fsf",		MTFSF,			O_RDONLY,	1 },
	{ "bsf",		MTBSF,			O_RDONLY,	1 },
	{ "asf",		MTASF,			O_RDONLY,	1 },
	{ "fsr",		MTFSR,			O_RDONLY,	1 },
	{ "bsr",		MTBSR,			O_RDONLY,	1 },
	{ "rewind",		MTREW,			O_RDONLY,	0 },
	{ "offline",		MTOFFL,			O_RDONLY,	0 },
	{ "rewoffl",		MTOFFL,			O_RDONLY,	0 },
	{ "status",		MTNOP,			O_RDONLY,	0 },
	{ "retension",		MTRETEN,		O_RDONLY,	0 },
	{ "erase",		MTERASE,		O_RDWR,		0 },
	{ "eom",		MTEOM,			O_RDONLY,	0 },
	{ "nbsf",		MTNBSF,			O_RDONLY,	1 },
	{ "reserve",		MTIOCRESERVE,		O_RDONLY,	0 },
	{ "release",		MTIOCRELEASE,		O_RDONLY,	0 },
	{ "forcereserve",	MTIOCFORCERESERVE,	O_UNLOAD,	0 },
	{ "config",		MTIOCGETDRIVETYPE,	O_UNLOAD,	0 },
	{ "fssf",		MTFSSF,			O_RDONLY,	1 },
	{ "bssf",		MTBSSF,			O_RDONLY,	1 },
	{ "tell",		MTTELL,			O_RDONLY,	0 },
	{ "seek",		MTSEEK,			O_RDONLY,	1 },
	{ "load",		MTLOAD,			O_UNLOAD,	0 },
	{ "lock",		MTLOCK,			O_RDONLY,	0 },
	{ "unlock",		MTUNLOCK,		O_RDONLY,	0 },
	{ 0 }
};


int
main(int argc, char **argv)
{
	char *cp;
	char *tape;
	int mtfd;
	struct commands const *comp;
	struct mtget mt_status;
	struct mtlop mt_com;

	if (argc > 2 && (equal(argv[1], "-t") || equal(argv[1], "-f"))) {
		argc -= 2;
		tape = argv[2];
		argv += 2;
	} else {
		tape = getenv("TAPE");
		if (tape == NULL) {
			tape = DEFAULT_NRW_TAPE;
		}
	}

	if (argc < 2) {
		(void) fprintf(stderr,
		    "usage: mt [ -f device ] command [ count ]\n");
		return (1);
	}

	cp = argv[1];
	for (comp = com; comp->c_name != NULL; comp++) {
		if (strncmp(cp, comp->c_name, strlen(cp)) == 0) {
			break;
		}
	}

	if (comp->c_name == NULL) {
		(void) fprintf(stderr, "mt: unknown command: %s\n", cp);
		return (1);
	}

	mtfd = open(tape, comp->c_oflag);
	if (mtfd < 0) {

		/*
		 * Provide additional error message decoding since
		 * we need additional error codes to fix them problem.
		 */
		if (errno == EIO) {
			(void) fprintf(stderr,
			    "%s: no tape loaded or drive offline\n", tape);
		} else if (errno == EACCES) {
			(void) fprintf(stderr,
			    "%s: write protected or reserved.\n", tape);
		} else {
			perror(tape);
		}
		return (1);
	}

	if (comp->c_code == MTIOCFORCERESERVE ||
	    comp->c_code == MTIOCRESERVE ||
	    comp->c_code == MTIOCRELEASE)  {
		/*
		 * Handle all MTIOC ioctls used in
		 * reservation/release/takeownership.
		 */
		if (ioctl(mtfd, comp->c_code) < 0) {
			perror("mt");
			return (2);
		}
	} else if (comp->c_code == MTASF) {
		/*
		 * Handle absolute file positioning.  Ask tape driver
		 * where tape is and then skip to desired file.  If
		 * driver doesn't support get location ioctl, rewind
		 * the tape and then space to the desired file.
		 */
		int usecnt;
		daddr_t mt_fileno;

		usecnt = argc > 2 && comp->c_usecnt;
		mt_fileno = usecnt ? atol(argv[2]) : 1;
		if (mt_fileno < 0) {
			(void) fprintf(stderr, "mt: negative file number\n");
			return (1);
		}
		(void) ioctl(mtfd, MTIOCGET, (char *)&mt_status);
		if (ioctl(mtfd, MTIOCGET, (char *)&mt_status) < 0) {
			perror("mt");
			return (2);
		}
		/*
		 * Check if device supports reporting current file
		 * tape file position.  If not, rewind the tape, and
		 * space forward.
		 *
		 * If file number is -1 tape position is unknown!
		 */
		if ((mt_status.mt_flags & MTF_ASF) == 0 ||
		    (mt_status.mt_fileno == -1)) {
			/* printf("mt: rewind\n"); */
			mt_com.mt_count = 1;
			mt_com.mt_op = MTREW;
			if (ioctl(mtfd, MTIOCLTOP, &mt_com) < 0) {
				(void) fprintf(stderr, "%s %s %ld ",
				    tape, comp->c_name, mt_fileno);
				perror("mt");
				return (2);
			}
			/* Needed to rewind which worked now correct fileno */
			mt_status.mt_fileno = 0;
			mt_status.mt_blkno = 0;
		}
		if (mt_fileno < mt_status.mt_fileno) {
			mt_com.mt_op = MTNBSF;
			mt_com.mt_count = mt_status.mt_fileno - mt_fileno;
			/* printf("mt: bsf= %d\n", mt_com.mt_count); */
		} else {
			mt_com.mt_op = MTFSF;
			mt_com.mt_count =  mt_fileno - mt_status.mt_fileno;
			/* printf("mt: fsf= %d\n", mt_com.mt_count); */
		}
		if (ioctl(mtfd, MTIOCLTOP, &mt_com) < 0) {
			(void) fprintf(stderr, "%s %s %ld ", tape, comp->c_name,
			    mt_fileno);
			perror("failed");
			return (2);
		}
	} else if (comp->c_code == MTIOCGETDRIVETYPE) {
		return (print_config(mtfd));

	/* Handle regular mag tape ioctls */
	} else if (comp->c_code != MTNOP) {
		int usecnt;

		mt_com.mt_op = comp->c_code;
		usecnt = argc > 2 && comp->c_usecnt;
		mt_com.mt_count = (usecnt ? atoll(argv[2]) : 1);
		if (mt_com.mt_count < 0) {
			(void) fprintf(stderr, "mt: negative %s count\n",
			    comp->c_name);
			return (1);
		}
		if (ioctl(mtfd, MTIOCLTOP, &mt_com) < 0) {
			/*
			 * If we asked for a seek and it returns a tell
			 * we attempted to seek more then there was.
			 */
			if (mt_com.mt_op == MTTELL &&
			    comp->c_code == MTSEEK) {
				(void) printf("partial seek:at block = %llu.\n",
				    mt_com.mt_count);
			} else {
				(void) fprintf(stderr, "%s %s %lld ", tape,
				    comp->c_name, mt_com.mt_count);
				perror("failed");
			}
			return (2);
		}
		if (mt_com.mt_op == MTTELL) {
			(void) printf("At block = %llu.\n", mt_com.mt_count);
		}


	/* Handle status ioctl */
	} else {
		if (ioctl(mtfd, MTIOCGET, (char *)&mt_status) < 0) {
			perror("mt");
			return (2);
		}
		return (status(mtfd, &mt_status));
	}
	return (0);
}

static int
print_config(int mtfd)
{
	struct mtdrivetype mdt;
	struct mtdrivetype_request mdt_req;
	char cfgname[48];
	char tmp[2];
	char *name;
	int i;

	mdt_req.size = sizeof (mdt);
	mdt_req.mtdtp = &mdt;

	if (ioctl(mtfd, MTIOCGETDRIVETYPE, &mdt_req) != 0) {
		perror("mt config");
		return (2);
	}

	/*
	 * remove trailing spaces from product id.
	 */
	for (i = VIDPIDLEN; i; i--) {
		if (isspace(mdt.vid[i]) || mdt.vid[i] == '*') {
			mdt.vid[i] = 0;
		} else if (mdt.vid[i] == 0) {
			continue;
		} else {
			break;
		}
	}

	/*
	 * If this is a generic name display the Vid and Pid instead.
	 */
	if (strstr(mdt.name, "Vendor '") == NULL) {
		name = mdt.name;
	} else {
		name = mdt.vid;
	}

	/*
	 * Attempt to create a configuration name using vid and pid.
	 */
	(void) strcpy(cfgname, "CFG");

	for (tmp[1] = i = 0; i < VIDPIDLEN; i++) {
		if (!isalnum(name[i]))
			continue;
		if (isspace(name[i]))
			continue;
		tmp[0] = toupper(name[i]);
		(void) strncat(cfgname, tmp, 1);
	}

	(void) printf("\"%s\", \"%s\", \"%s\";\n", mdt.vid, name, cfgname);

	/*
	 * Don't want show some bits, ST_DYNAMIC is set in the driver
	 * so one can tell that its not a compiled in config.
	 * The ST_LONG_ERASE and ST_LONG_TIMEOUTS are not displayed
	 * becouse the timeout values below already reflect them being
	 * set.
	 * Also ST_KNOWS_MEDIA is not displayed as it can not be configured
	 * from an st.conf entry.
	 */
	(void) printf("%s = 2,0x%X,%d,0x%X,", cfgname,
	    mdt.type, mdt.bsize, mdt.options &
	    ~(ST_DYNAMIC | ST_LONG_ERASE | ST_LONG_TIMEOUTS | ST_KNOWS_MEDIA));

	(void) printf("4,0x%2.2X,0x%2.2X,0x%2.2X,0x%2.2X,%d,",
	    mdt.densities[0], mdt.densities[1], mdt.densities[2],
	    mdt.densities[3], mdt.default_density >> 3);

	(void) printf("%d,%d,%d,%d,%d,%d,%d;\n", mdt.non_motion_timeout,
	    mdt.io_timeout, mdt.rewind_timeout, mdt.space_timeout,
	    mdt.load_timeout, mdt.unload_timeout, mdt.erase_timeout);

	return (0);
}

/*
 * Interpret the status buffer returned
 */
static int
status(int mtfd, struct mtget *bp)
{
	struct mtdrivetype mdt;
	struct mtdrivetype_request mdt_req;
	const char *name = (char *)NULL;

	/*
	 * Make a call to MTIOCGETDRIVETYPE ioctl, Also use old method
	 * of MT_TAPE_INFO for now, but MT_TAPE_INFO should dissapear in 2.7
	 */
	mdt_req.size = sizeof (struct mtdrivetype);
	mdt_req.mtdtp = &mdt;

	if (ioctl(mtfd, MTIOCGETDRIVETYPE, &mdt_req) == 0) {
		name = mdt.name;
		if (strstr(mdt.name, "Vendor '") != NULL) {
			(void) printf("Unconfigured Drive: ");
		}
	} else {
		perror("mt drivetype");
		return (2);
	}

	/* Handle SCSI tape drives specially. */
	if ((bp->mt_flags & MTF_SCSI)) {
		if (name == (char *)NULL) {
			name = "SCSI";
		}


		(void) printf("%s tape drive:\n", name);

		(void) printf("   sense key(0x%x)= %s   residual= %ld   ",
		    bp->mt_erreg, print_key(bp->mt_erreg), bp->mt_resid);
		(void) printf("retries= %d\n", bp->mt_dsreg);
		/*
		 * Can overflow the signed numbers.
		 * fileno will be -1 on error but all other positions are
		 * positive. blkno will never be negative.
		 */
		if (bp->mt_fileno == -1) {
			(void) printf("   file no= -1   block no= %lu\n",
			    (unsigned long)bp->mt_blkno);
		} else {
			(void) printf("   file no= %lu   block no= %lu\n",
			    (unsigned long)bp->mt_fileno,
			    (unsigned long)bp->mt_blkno);
		}
		if ((bp->mt_flags & MTF_WORM_MEDIA) != 0) {
			(void) printf("   WORM media\n");
		}
	} else {
		/* Handle non-SCSI drives here. */
		if (name == NULL) {
			(void) printf("unknown tape drive type (0x%x)\n",
			    mdt.type);
			return (2);
		}
		(void) printf("%s tape drive:\n   residual= %ld", name,
		    bp->mt_resid);
		printreg("   ds", (ushort_t)bp->mt_dsreg, 0);
		printreg("   er", (ushort_t)bp->mt_erreg, 0);
		(void) putchar('\n');
	}
	return (0);
}


/*
 * Define SCSI sense key error messages.
 *
 * The first 16 sense keys are SCSI standard
 * sense keys. The keys after this are
 * Sun Specifice 'sense' keys- e.g., crap.
 */

static char *sense_keys[] = {
	"No Additional Sense",		/* 0x00 */
	"Soft Error",			/* 0x01 */
	"Not Ready",			/* 0x02 */
	"Media Error",			/* 0x03 */
	"Hardware Error",		/* 0x04 */
	"Illegal Request",		/* 0x05 */
	"Unit Attention",		/* 0x06 */
	"Write Protected",		/* 0x07 */
	"Blank Check",			/* 0x08 */
	"Vendor Unique",		/* 0x09 */
	"Copy Aborted",			/* 0x0a */
	"Aborted Command",		/* 0x0b */
	"Equal Error",			/* 0x0c */
	"Volume Overflow",		/* 0x0d */
	"Miscompare Error",		/* 0x0e */
	"Reserved",			/* 0x0f */
#ifdef	sun
	"fatal",			/* 0x10 */
	"timeout",			/* 0x11 */
	"EOF",				/* 0x12 */
	"EOT",				/* 0x13 */
	"length error",			/* 0x14 */
	"BOT",				/* 0x15 */
	"wrong tape media",		/* 0x16 */
#endif
};

/*
 * Return the text string associated with the sense key value.
 */
static char *
print_key(short key_code)
{
	static char unknown[32];

	if ((key_code >= 0) &&
	    (key_code < (sizeof (sense_keys) / sizeof (sense_keys[0])))) {
		return (sense_keys[key_code]);
	}

	(void) sprintf(unknown, "unknown sense key: 0x%x",
	    (unsigned int) key_code);
	return (unknown);
}


/*
 * Print a register a la the %b format of the kernel's printf
 */
static void
printreg(char *s, ushort_t v, char *bits)
{
	int i, any = 0;
	char c;

	if (bits && *bits == 8) {
		(void) printf("%s = %o", s, v);
	} else {
		(void) printf("%s = %x", s, v);
	}
	bits++;
	if (v && bits) {
		(void) putchar('<');
		while ((i = *bits++) != 0) {
			if (v & (1 << (i-1))) {
				if (any) {
					(void) putchar(',');
				}
				any = 1;
				for (; (c = *bits) > 32; bits++) {
					(void) putchar(c);
				}
			} else {
				for (; *bits > 32; bits++)
					;
			}
		}
		(void) putchar('>');
	}
}
