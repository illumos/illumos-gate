/*
 * Copyright (c) 2003, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is part of a stress test for ::Exacct and libexacct.
 * See README for details.
 */

/* Turn largefile support on. */
#define	_FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <exacct.h>
#include <exacct_impl.h>

static char *ea_errstr[] = {
	"EXR_OK",
	"EXR_SYSCALL_FAIL",
	"EXR_CORRUPT_FILE",
	"EXR_EOF",
	"EXR_NO_CREATOR",
	"EXR_INVALID_BUF",
	"EXR_NOTSUPP",
	"EXR_UNKN_VERSION",
	"EXR_INVALID_OBJ",
};

#define	LOGSZ 100
#define	LINESZ 81
static char log[LOGSZ][LINESZ];
static int log_op, log_pos;

static char *type_str(ea_object_type_t type)
{
	switch (type & EXT_TYPE_MASK) {
	case EXT_NONE:
		return ("NONE");
	case EXT_UINT8:
		return ("UINT8");
	case EXT_UINT16:
		return ("UINT16");
	case EXT_UINT32:
		return ("UINT32");
	case EXT_UINT64:
		return ("UINT64");
	case EXT_DOUBLE:
		return ("DOUBLE");
	case EXT_STRING:
		return ("STRING");
	case EXT_EXACCT_OBJECT:
		return ("OBJECT");
	case EXT_RAW:
		return ("RAW");
	case EXT_GROUP:
		return ("GROUP");
	default:
		return ("INVALID");
	}
}

static void logmsg(const char *msg, char dir, ea_file_t *f, ea_object_t *obj)
{
	ea_file_impl_t *fi;
	off_t pos;
	char buf[LINESZ];
	char posbuf[10];

	fi = (ea_file_impl_t *)f;
	pos = ftello(fi->ef_fp);
	log_op++;
	if (fi->ef_ndeep < 0) {
		(void) strlcpy(posbuf, "0/0", sizeof (posbuf));
	} else {
		(void) snprintf(posbuf, sizeof (posbuf), "%d/%d",
		    fi->ef_depth[fi->ef_ndeep].efd_obj + 1,
		    fi->ef_depth[fi->ef_ndeep].efd_nobjs);
	}
	(void) snprintf(log[log_pos], LINESZ,
	    "%-6d %c off=0x%-5llx depth=%-2d pos=%-7s adv=0x%-3llx %s",
	    log_op, dir, pos, fi->ef_ndeep, posbuf, fi->ef_advance, msg);
	if (obj != NULL) {
		if ((obj->eo_type & EXT_TYPE_MASK) == EXT_GROUP) {
			(void) snprintf(buf, LINESZ, " %s #%d len=%d",
			    type_str(obj->eo_catalog),
			    obj->eo_catalog & EXD_DATA_MASK,
			    obj->eo_group.eg_nobjs);
		} else {
			(void) snprintf(buf, LINESZ, " %s #%d",
			    type_str(obj->eo_catalog),
			    obj->eo_catalog & EXD_DATA_MASK);
		}
		(void) strlcat(log[log_pos], buf, LINESZ);
	}
	log_pos = (log_pos + 1) % LOGSZ;
}

static void die(ea_file_t *f, const char *msg)
{
	int i, l;
	char buf[LINESZ];

	bzero(buf, sizeof (buf));
	if (ea_error() == EXR_SYSCALL_FAIL) {
		(void) strlcat(buf, strerror(errno), sizeof (buf));
	}
	(void) printf("\nError at offset 0x%lx: %s: %s %s\n",
	    ftell(((ea_file_impl_t *)f)->ef_fp), msg,
	    ea_errstr[ea_error()], buf);
	(void) printf("Last %d operations:\n", LOGSZ);
	for (i = LOGSZ, l = log_pos; i > 0; i--, l = (l + 1) % LOGSZ) {
		if (log[l][0] != '\0') {
			(void) printf("%s\n", log[l]);
		}
	}
	exit(1);
}

/* ARGSUSED */
static void stop(int sig)
{
	exit(2);
}

static int
do_reads(ea_file_t *f, char dir, int sz)
{
	ea_object_t	obj;
	unsigned char	act;

	bzero(&obj, sizeof (obj));
	while (sz--) {

		act = 0x01 << (lrand48() & 0x01);

		/* If reading backwards */
		if (dir == 'B') {
			logmsg("> ea_previous_object", dir, f, NULL);
			if (ea_previous_object(f, &obj) == EO_ERROR) {
				if (ea_error() == EXR_EOF) {
					logmsg("! SOF", dir, f, NULL);
					return ('F');
				} else {
					die(f, "ea_previous_object");
				}
			}
			logmsg("< ea_previous_object", dir, f, NULL);
		}

		/* Do a ea_next_object 50% of the time */
		if (act & 0x01) {
			logmsg("> ea_next_object", dir, f, NULL);
			if (ea_next_object(f, &obj) == EO_ERROR) {
				if (ea_error() == EXR_EOF) {
					logmsg("! EOF", dir, f, NULL);
					return (dir == 'F' ? 'B' : 'F');
				} else {
					die(f, "ea_next_object");
				}
			}
			logmsg("< ea_next_object", dir, f, NULL);
		}

		/* Do a ea_get_object 50% of the time */
		if (act & 0x02) {
			logmsg("> ea_get_object", dir, f, NULL);
			if (ea_get_object(f, &obj) == EO_ERROR) {
				if (ea_error() == EXR_EOF) {
					logmsg("! EOF", dir, f, NULL);
					return (dir == 'F' ? 'B' : 'F');
				} else {
					die(f, "ea_get_object");
				}
			}
			logmsg("< ea_get_object", dir, f, &obj);
			(void) ea_free_item(&obj, EUP_ALLOC);
		}

		/* If reading backwards */
		if (dir == 'B') {
			logmsg("> ea_previous_object", dir, f, NULL);
			if (ea_previous_object(f, &obj) == EO_ERROR) {
				if (ea_error() == EXR_EOF) {
					logmsg("! SOF", dir, f, NULL);
					return ('F');
				} else {
					die(f, "ea_get_object");
				}
			}
			logmsg("< ea_previous_object", dir, f, NULL);
		}
	}
	return (' ');
}

int
main(int argc, char **argv)
{
	int		iters, maxsz, sz;
	char		dir;
	ea_file_t	f;

	(void) signal(SIGINT, stop);
	(void) signal(SIGTERM, stop);
	(void) signal(SIGHUP, stop);

	if (argc != 4) {
		(void) fprintf(stderr,
		    "Usage: randtest <iters> <maxsz> <file>\n");
		return (2);
	}
	iters = atoi(argv[1]);
	maxsz = atoi(argv[2]);
	bzero(log, sizeof (log));
	log_pos = log_op = 0;

	if (ea_open(&f, argv[3], NULL, EO_HEAD, O_RDONLY, 0) == -1) {
		perror("open failed");
		return (1);
	}
	srand48((long)(gethrtime() & ~0L));
	dir = 'F';
	while (iters--) {
		if (dir == ' ') {
			dir = (lrand48() % 2) ? 'F' : 'B';
		}
		sz = (lrand48() % maxsz) + 1;
		dir = do_reads(&f, dir, sz);
	}
	(void) ea_close(&f);
	return (0);
}
