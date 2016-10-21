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

/* Copyright 2015, Richard Lowe. */

#include <err.h>
#include <errno.h>
#include <grp.h>
#include <libintl.h>
#include <procfs.h>
#include <project.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/secflags.h>
#include <sys/types.h>

#include <libproc.h>
#include <libzonecfg.h>

extern const char *__progname;

static void
print_flags(const char *set, secflagset_t flags)
{
	char buf[1024];

	secflags_to_str(flags, buf, sizeof (buf));
	(void) printf("\t%s:\t%s\n", set, buf);
}

/*
 * Structure defining idtypes known to the priocntl command
 * along with the corresponding names.
 * The idtype values themselves are defined in <sys/procset.h>.
 */
static struct idtypes {
	idtype_t	type;
	char		*name;
} idtypes [] = {
	{ P_ALL,	"all"		},
	{ P_CTID,	"contract"	},
	{ P_CTID,	"ctid"		},
	{ P_GID,	"gid"		},
	{ P_GID,	"group"		},
	{ P_PGID,	"pgid"		},
	{ P_PID,	"pid"		},
	{ P_PPID,	"ppid"		},
	{ P_PROJID,	"project"	},
	{ P_PROJID,	"projid"	},
	{ P_SID,	"session",	},
	{ P_SID,	"sid"		},
	{ P_SID,	"sid"		},
	{ P_TASKID,	"taskid"	},
	{ P_UID,	"uid"		},
	{ P_UID,	"user"		},
	{ P_ZONEID,	"zone"		},
	{ P_ZONEID,	"zoneid"	},
	{ 0, 		NULL		}
};

static int
str2idtype(char *idtypnm, idtype_t *idtypep)
{
	struct idtypes	*curp;

	for (curp = idtypes; curp->name != NULL; curp++) {
		if (strncasecmp(curp->name, idtypnm,
		    strlen(curp->name)) == 0) {
			*idtypep = curp->type;
			return (0);
		}
	}
	return (-1);
}

static id_t
getid(idtype_t type, char *value)
{
	struct passwd *pwd;
	struct group *grp;
	id_t ret;
	char *endp;

	switch (type) {
	case P_UID:
		if ((pwd = getpwnam(value)) != NULL)
			return (pwd->pw_uid);
		break;
	case P_GID:
		if ((grp = getgrnam(value)) != NULL)
			return (grp->gr_gid);
		break;
	case P_PROJID:
		if ((ret = getprojidbyname(value)) != (id_t)-1)
			return (ret);
		break;
	case P_ZONEID:
		if (zone_get_id(value, &ret) == 0)
			return (ret);
		break;
	default:
		break;
	}

	errno = 0;

	ret = (id_t)strtoul(value, &endp, 10);

	if ((errno != 0) || (*endp != '\0'))
		return ((id_t)-1);

	return (ret);
}

int
main(int argc, char **argv)
{
	secflagdelta_t act;
	psecflagwhich_t which = PSF_INHERIT;
	int ret = 0;
	int pgrab_flags = PGRAB_RDONLY;
	int opt;
	char *idtypename = NULL;
	idtype_t idtype = P_PID;
	boolean_t usage = B_FALSE;
	boolean_t e_flag = B_FALSE;
	boolean_t l_flag = B_FALSE;
	boolean_t s_flag = B_FALSE;
	int errc = 0;

	while ((opt = getopt(argc, argv, "eFi:ls:")) != -1) {
		switch (opt) {
		case 'e':
			e_flag = B_TRUE;
			break;
		case 'F':
			pgrab_flags |= PGRAB_FORCE;
			break;
		case 'i':
			idtypename = optarg;
			break;
		case 's':
			s_flag = B_TRUE;
			if ((strlen(optarg) >= 2) &&
			    ((optarg[1] == '='))) {
				switch (optarg[0]) {
				case 'L':
					which = PSF_LOWER;
					break;
				case 'U':
					which = PSF_UPPER;
					break;
				case 'I':
					which = PSF_INHERIT;
					break;
				case 'E':
					errx(1, "the effective flags cannot "
					    "be changed", optarg[0]);
				default:
					errx(1, "unknown security flag "
					    "set: '%c'", optarg[0]);
				}

				optarg += 2;
			}

			if (secflags_parse(NULL, optarg, &act) == -1)
				errx(1, "couldn't parse security flags: %s",
				    optarg);
			break;
		case 'l':
			l_flag = B_TRUE;
			break;
		default:
			usage = B_TRUE;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (l_flag && ((idtypename != NULL) || s_flag || (argc != 0)))
		usage = B_TRUE;
	if ((idtypename != NULL) && !s_flag)
		usage = B_TRUE;
	if (e_flag && !s_flag)
		usage = B_TRUE;
	if (!l_flag && argc <= 0)
		usage = B_TRUE;

	if (usage) {
		(void) fprintf(stderr,
		    gettext("usage:\t%s [-F] { pid | core } ...\n"),
		    __progname);
		(void) fprintf(stderr,
		    gettext("\t%s -s spec [-i idtype] id ...\n"),
		    __progname);
		(void) fprintf(stderr,
		    gettext("\t%s -s spec -e command [arg]...\n"),
		    __progname);
		(void) fprintf(stderr, gettext("\t%s -l\n"), __progname);
		return (2);
	}

	if (l_flag) {
		secflag_t i;
		const char *name;

		for (i = 0; (name = secflag_to_str(i)) != NULL; i++)
			(void) printf("%s\n", name);
		return (0);
	} else if (s_flag && e_flag) {
		/*
		 * Don't use the strerror() message for EPERM, "Not Owner"
		 * which is misleading.
		 */
		errc = psecflags(P_PID, P_MYID, which, &act);
		switch (errc) {
		case 0:
			break;
		case EPERM:
			errx(1, gettext("failed setting "
			    "security-flags: Permission denied"));
			break;
		default:
			err(1, gettext("failed setting security-flags"));
		}

		(void) execvp(argv[0], &argv[0]);
		err(1, "%s", argv[0]);
	} else if (s_flag) {
		int i;
		id_t id;

		if (idtypename != NULL)
			if (str2idtype(idtypename, &idtype) == -1)
				errx(1, gettext("No such id type: '%s'"),
				    idtypename);

		for (i = 0; i < argc; i++) {
			if ((id = getid(idtype, argv[i])) == (id_t)-1) {
				errx(1, gettext("invalid or non-existent "
				    "identifier: '%s'"), argv[i]);
			}

			/*
			 * Don't use the strerror() message for EPERM, "Not
			 * Owner" which is misleading.
			 */
			if (psecflags(idtype, id, which, &act) != 0) {
				switch (errno) {
				case EPERM:
					errx(1, gettext("failed setting "
					    "security-flags: "
					    "Permission denied"));
					break;
				default:
					err(1, gettext("failed setting "
					    "security-flags"));
				}
			}
		}

		return (0);
	}

	/* Display the flags for the given pids */
	while (argc-- > 0) {
		struct ps_prochandle *Pr;
		const char *arg;
		psinfo_t psinfo;
		prsecflags_t *psf;
		int gcode;

		if ((Pr = proc_arg_grab(arg = *argv++, PR_ARG_ANY,
		    pgrab_flags, &gcode)) == NULL) {
			warnx(gettext("cannot examine %s: %s"),
			    arg, Pgrab_error(gcode));
			ret = 1;
			continue;
		}

		(void) memcpy(&psinfo, Ppsinfo(Pr), sizeof (psinfo_t));
		proc_unctrl_psinfo(&psinfo);

		if (Pstate(Pr) == PS_DEAD) {
			(void) printf(gettext("core '%s' of %d:\t%.70s\n"),
			    arg, (int)psinfo.pr_pid, psinfo.pr_psargs);
		} else {
			(void) printf("%d:\t%.70s\n",
			    (int)psinfo.pr_pid, psinfo.pr_psargs);
		}

		if (Psecflags(Pr, &psf) != 0)
			err(1, gettext("cannot read secflags of %s"), arg);

		print_flags("E", psf->pr_effective);
		print_flags("I", psf->pr_inherit);
		print_flags("L", psf->pr_lower);
		print_flags("U", psf->pr_upper);

		Psecflags_free(psf);
		Prelease(Pr, 0);
	}

	return (ret);
}
