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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <sys/reboot.h>
#include <sys/cmn_err.h>
#include <sys/bootconf.h>
#include <sys/promif.h>
#include <sys/obpdefs.h>
#include <sys/sunddi.h>
#include <sys/systm.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <util/getoptstr.h>

char *kobj_kmdb_argv[11];	/* 10 arguments and trailing NULL */

/*
 * Parse the boot line to determine boot flags.
 */
void
bootflags(struct bootops *ops)
{
	struct gos_params params;
	uchar_t num_O_opt = 0;
	char *cp;
	int c;
	char scratch[BOOTARGS_MAX];

	if (BOP_GETPROP(ops, "bootargs", kern_bootargs) == -1) {
		boothowto |= RB_ASKNAME;
		return;
	}

	(void) BOP_GETPROP(ops, "boot-file", kern_bootfile);

	cp = kern_bootargs;

#if defined(_OBP)
	/*
	 * Sparc only, _OBP isn't defined on x86 any more.
	 */
	if (cp[0] != '-') {
		/* if user booted kadb or kmdb, load kmdb */
		if (cp[0] == 'k' && (cp[1] == 'a' || cp[1] == 'm') &&
		    cp[2] == 'd' && cp[3] == 'b' &&
		    (cp[4] == ' ' || cp[4] == '	' || cp[4] == 0))
			boothowto |= RB_KMDB;
		SKIP_WORD(cp);		/* Skip the kernel's filename. */
	}
#endif
	SKIP_SPC(cp);

#if defined(_OBP)
	/* skip bootblk args */
	params.gos_opts = "abcdDf:F:gGHhi:km:o:O:rsvVwxZ:";
#else
	params.gos_opts = "abcdgGhi:km:O:rsvwx";
#endif
	params.gos_strp = cp;
	getoptstr_init(&params);
	while ((c = getoptstr(&params)) != -1) {

		switch (c) {
		case 'a':
			boothowto |= RB_ASKNAME;
			break;
		case 'b':
			boothowto |= RB_NOBOOTRC;
			break;
		case 'c':
			boothowto |= RB_CONFIG;
			break;
		case 'd':
			boothowto |= RB_DEBUGENTER;
			break;
#if defined(_OBP)
		case 'D':
		case 'F':
			break;
		case 'f':
			(void) prom_setprop(prom_optionsnode(), "diag-level",
			    (char *)params.gos_optargp,
			    params.gos_optarglen + 1);
			break;
#endif
		case 'g':
			boothowto |= RB_FORTHDEBUG;
			break;
		case 'G':
			boothowto |= RB_FORTHDEBUGDBP;
			break;
		case 'h':
			boothowto |= RB_HALT;
			break;
#if defined(_OBP)
		case 'H':
			break;
#endif
		case 'i':
			if (params.gos_optarglen + 1 > sizeof (initname)) {
				_kobj_printf(ops, "krtld: initname too long.  "
				    "Ignoring.\n");
			} else {
				(void) strncpy(initname, params.gos_optargp,
				    params.gos_optarglen);
				initname[params.gos_optarglen] = '\0';
			}
			break;
		case 'k':
			boothowto |= RB_KMDB;
			break;
		case 'm':
			if (strlen(initargs) + 3 + params.gos_optarglen + 1 >
			    sizeof (initargs)) {
				_kobj_printf(ops,
				    "unix: init options too long.  "
				    "Ignoring -m.\n");
				break;
			}
			/* gos_optargp is not null terminated */
			(void) strncpy(scratch, params.gos_optargp,
			    params.gos_optarglen);
			scratch[params.gos_optarglen] = '\0';
			(void) strlcat(initargs, "-m ", sizeof (initargs));
			(void) strlcat(initargs, scratch,
			    sizeof (initargs));
			(void) strlcat(initargs, " ", sizeof (initargs));
			break;
#if defined(_OBP)
		/* Ignore legacy wanboot argument meant for standalone */
		case 'o':
			break;
#endif
		case 'O': {
			char **str = &kobj_kmdb_argv[num_O_opt];

			if (++num_O_opt > (sizeof (kobj_kmdb_argv) /
			    sizeof (char *)) - 1) {
				_kobj_printf(ops, "krtld: too many kmdb "
				    "options - ignoring option #%d.\n",
				    num_O_opt);
				continue;
			}

			*str = kobj_alloc(params.gos_optarglen + 1, KM_TMP);
			(void) strncpy(*str, params.gos_optargp,
			    params.gos_optarglen);
			(*str)[params.gos_optarglen] = '\0';
			break;
		}
		case 'r':
			if (strlen(initargs) + 3 + 1 > sizeof (initargs)) {
				_kobj_printf(ops, "unix: init options too "
				    "long.  Ignoring -r.\n");
				break;
			}
			boothowto |= RB_RECONFIG;
			(void) strlcat(initargs, "-r ", sizeof (initargs));
			break;
		case 's':
			if (strlen(initargs) + 3 + 1 > sizeof (initargs)) {
				_kobj_printf(ops, "unix: init options too "
				    "long.  Ignoring -s.\n");
				break;
			}
			boothowto |= RB_SINGLE;
			(void) strlcat(initargs, "-s ", sizeof (initargs));
			break;
		case 'v':
			if (strlen(initargs) + 3 + 1 > sizeof (initargs)) {
				_kobj_printf(ops, "unix: init options too "
				    "long.  Ignoring -v.\n");
				break;
			}
			boothowto |= RB_VERBOSE;
			(void) strlcat(initargs, "-v ", sizeof (initargs));
			break;
#if defined(_OBP)
		case 'V':
			break;
		case 'Z':
			break;
#endif
		case 'w':
			boothowto |= RB_WRITABLE;
			break;
		case 'x':
			boothowto |= RB_NOBOOTCLUSTER;
			break;
		case '?':
			switch (params.gos_last_opt) {
			case 'i':
				_kobj_printf(ops, "krtld: Required argument "
				    "for -i flag missing.  Ignoring.\n");
				break;
			default:
				_kobj_printf(ops, "krtld: Ignoring invalid "
				    "kernel option -%c.\n",
				    params.gos_last_opt);
			}
			break;
		default:
			_kobj_printf(ops, "krtld: Ignoring unimplemented "
			    "option -%c.\n", c);
		}
	}

	if ((boothowto & (RB_DEBUGENTER | RB_KMDB)) == RB_DEBUGENTER) {
		_kobj_printf(ops, "krtld: -d is not valid without -k.\n");
		boothowto &= ~RB_DEBUGENTER;
	}

	if (*params.gos_strp) {
		/* Unused arguments. */
		if (params.gos_strp[0] == '-' && ISSPACE(params.gos_strp[1])) {
			/*EMPTY*/
			/* Lousy install arguments.  Silently ignore. */
		} else {
			_kobj_printf(ops, "krtld: Unused kernel arguments: "
			    "`%s'.\n", params.gos_strp);
		}
	}
}
