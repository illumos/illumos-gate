/*
 * Open Boot Prom eeprom utility
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/openpromio.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Usage:  % eeprom [-v] [-f promdev] [-]
 *	   % eeprom [-v] [-f promdev] field[=value] ...
 */

/*
 * 128 is the size of the largest (currently) property name buffer
 * 8192 - MAXPROPSIZE - sizeof (int) is the size of the largest
 * (currently) property value, viz. nvramrc.
 * the sizeof(u_int) is from struct openpromio
 */

#define	MAXPROPSIZE	128
#define	MAXNAMESIZE	MAXPROPSIZE
#define	MAXVALSIZE	(8192 - MAXPROPSIZE - sizeof (uint_t))
#define	BUFSIZE		(MAXPROPSIZE + MAXVALSIZE + sizeof (uint_t))
typedef union {
	char buf[BUFSIZE];
	struct openpromio opp;
} Oppbuf;

extern int _error(int do_perror, char *fmt, ...);
extern void setprogname(char *);
static int get_password(char *, int);
extern int loadlogo(char *, int, int, char *);

#define	NO_PERROR	0
#define	PERROR		1

static int prom_fd;
static char *promdev;
static int verbose;

static void do_var(char *);
static void dump_all();
static void print_one(char *);
static void set_one(char *, char *);
static void promclose();
static int promopen(int);

static int getpropval(struct openpromio *);
static int setpropval(struct openpromio *);

static char *badarchmsg = "Architecture does not support this command.\n";

typedef	void (*func)();


/* We have to special-case two properties related to security */
static void i_secure();
static void i_passwd(), o_passwd();
static void i_oemlogo();

/*
 * It's unfortunate that we have to know the names of certain properties
 * in this program (the whole idea of openprom was to avoid it), but at
 * least we can isolate them to these defines here.
 */
#define	PASSWORD_PROPERTY "security-password"
#define	MODE_PROPERTY "security-mode"
#define	LOGO_PROPERTY "oem-logo"
#define	PW_SIZE 8

/*
 * Unlike the old-style eeprom command, where every property needed an
 * i_foo and an o_foo function, we only need them when the default case
 * isn't sufficient.
 */
static struct	opvar {
	char	*name;
	func	in;
	func	out;
} opvar[] = {
#define	e(n, i, o)	{n, i, o}
	e(MODE_PROPERTY,	i_secure,	(func)NULL),
	e(PASSWORD_PROPERTY,	i_passwd,	o_passwd),
	e(LOGO_PROPERTY,	i_oemlogo,	(func)NULL),
	{ (char *)NULL, (func)NULL, (func)NULL}
#undef e
};


/*
 * sun4c openprom
 */

int
main(int argc, char **argv)
{
	int c;
	extern char *optarg;
	extern int optind;

	promdev = "/dev/openprom";

	while ((c = getopt(argc, argv, "cif:v")) != -1)
		switch (c) {
		case 'c':
		case 'i':
			/* ignore for openprom */
			break;
		case 'v':
			verbose++;
			break;
		case 'f':
			promdev = optarg;
			break;
		default:
			exit(_error(NO_PERROR,
			    "Usage: %s [-v] [-f prom-device] "
			    "[variable[=value] ...]", argv[0]));
		}

	setprogname(argv[0]);

	/*
	 * If no arguments, dump all fields.
	 */
	if (optind >= argc) {
		dump_all();
		exit(0);
	}

	while (optind < argc) {
		/*
		 * If "-" specified, read variables from stdin.
		 */
		if (strcmp(argv[optind], "-") == 0) {
			int c;
			char *nl, line[BUFSIZE];

			while (fgets(line, sizeof (line), stdin) != NULL) {
				/* zap newline if present */
				if (nl = strchr(line, '\n'))
					*nl = 0;
				/* otherwise discard rest of line */
				else
					while ((c = getchar()) != '\n' &&
					    c != EOF)
						/* nothing */;

				do_var(line);
			}
			clearerr(stdin);
		}
		/*
		 * Process each argument as a variable print or set request.
		 */
		else
			do_var(argv[optind]);

		optind++;
	}
	return (0);
}

/*
 * Print or set an EEPROM field.
 */
static void
do_var(char *var)
{
	char *val;

	val = strchr(var, '=');

	if (val == NULL) {
		/*
		 * print specific property
		 */
		if (promopen(O_RDONLY))  {
			(void) fprintf(stderr, badarchmsg);
			exit(1);
		}
		print_one(var);
	} else {
		/*
		 * set specific property to value
		 */
		*val++ = '\0';

		if (promopen(O_RDWR))  {
			(void) fprintf(stderr, badarchmsg);
			exit(1);
		}
		set_one(var, val);
	}
	promclose();
}

/*
 * Print all properties and values
 */
static void
dump_all()
{
	Oppbuf	oppbuf;
	struct openpromio *opp = &(oppbuf.opp);

	if (promopen(O_RDONLY))  {
		(void) fprintf(stderr, badarchmsg);
		exit(1);
	}
	/* get first prop by asking for null string */
	(void) memset(oppbuf.buf, '\0', BUFSIZE);
	/* CONSTCOND */
	while (1) {
		/*
		 * get property
		 */
		opp->oprom_size = MAXPROPSIZE;

		if (ioctl(prom_fd, OPROMNXTOPT, opp) < 0)
			exit(_error(PERROR, "OPROMNXTOPT"));

		if (opp->oprom_size == 0) {
			promclose();
			return;
		}
		print_one(opp->oprom_array);
	}
}

/*
 * Print one property and its value.
 */
static void
print_one(char *var)
{
	Oppbuf	oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	char bootargs[MAXVALSIZE];

	if (strcmp(var, "bootcmd") == 0) {
		opp->oprom_size = MAXVALSIZE;
		if (ioctl(prom_fd, OPROMGETBOOTARGS, opp) < 0) {
			(void) _error(PERROR, "OPROMGETBOOTARGS");
			return;
		}
		(void) strlcpy(bootargs, opp->oprom_array, MAXVALSIZE);

		opp->oprom_size = MAXVALSIZE;
		if (ioctl(prom_fd, OPROMGETBOOTPATH, opp) < 0) {
			(void) _error(PERROR, "OPROMGETBOOTPATH");
			return;
		}
		(void) printf("%s=%s %s\n", var, opp->oprom_array, bootargs);
		return;
	}

	(void) strlcpy(opp->oprom_array, var, MAXNAMESIZE);
	if (getpropval(opp) || opp->oprom_size <= 0)
		(void) printf("%s: data not available.\n", var);
	else {
		/* If necessary, massage the output */
		struct opvar *v;

		for (v = opvar; v->name; v++)
			if (strcmp(var, v->name) == 0)
				break;

		if (v->name && v->out)
			(*v->out)(v->name, opp->oprom_array);
		else
			(void) printf("%s=%s\n", var, opp->oprom_array);
	}
}

/*
 * Set one property to the given value.
 */
static void
set_one(char *var, char *val)
{
	Oppbuf	oppbuf;
	struct openpromio *opp = &(oppbuf.opp);
	struct opvar *v;

	if (verbose) {
		(void) printf("old:");
		print_one(var);
	}

	/* If necessary, massage the input */

	for (v = opvar; v->name; v++)
		if (strcmp(var, v->name) == 0)
			break;

	if (v->name && v->in)
		(*v->in)(v->name, val, opp);
	else {
		int varlen = strlen(var) + 1;
		int vallen = strlen(val);

		if (varlen > MAXNAMESIZE) {
			(void) printf("%s: invalid property.\n", var);
			return;
		}
		if (vallen >= MAXVALSIZE) {
			(void) printf("%s: invalid property value.\n", var);
			return;
		}
		(void) strcpy(opp->oprom_array, var);
		(void) strcpy(opp->oprom_array + varlen, val);
		opp->oprom_size = varlen + vallen;
		if (setpropval(opp))
			(void) printf("%s: invalid property.\n", var);
	}

	if (verbose) {
		(void) printf("new:");
		print_one(var);
	}
}

static int
promopen(int oflag)
{
	/* CONSTCOND */
	while (1)  {
		if ((prom_fd = open(promdev, oflag)) < 0)  {
			if (errno == EAGAIN)
				continue;
			else if (errno == ENXIO)
				return (-1);
			else
				exit(_error(PERROR, "cannot open %s", promdev));
		} else
			break;
	}
	return (0);
}

static void
promclose()
{
	if (close(prom_fd) < 0)
		exit(_error(PERROR, "close error on %s", promdev));
}

static int
getpropval(struct openpromio *opp)
{
	opp->oprom_size = MAXVALSIZE;

	if (ioctl(prom_fd, OPROMGETOPT, opp) < 0)
		return (_error(PERROR, "OPROMGETOPT"));

	return (0);
}

static int
setpropval(struct openpromio *opp)
{
	/* Caller must set opp->oprom_size */

	if (ioctl(prom_fd, OPROMSETOPT, opp) < 0)
		return (_error(PERROR, "OPROMSETOPT"));
	return (0);
}


/*
 * The next set of functions handle the special cases.
 */

static void
i_oemlogo(char *var, char *val, struct openpromio *opp)
{
	int varlen = strlen(var) + 1;

	(void) strcpy(opp->oprom_array, var);	/* safe - we know the name */

	if (loadlogo(val, 64, 64, opp->oprom_array + varlen))
		exit(1);
	opp->oprom_size = varlen + 512;
	if (ioctl(prom_fd, OPROMSETOPT2, opp) < 0)
		exit(_error(PERROR, "OPROMSETOPT2"));
}

/*
 * Set security mode.
 * If oldmode was none, and new mode is not none, get and set password,
 * too.
 * If old mode was not none, and new mode is none, wipe out old
 * password.
 */
static void
i_secure(char *var, char *val, struct openpromio *opp)
{
	int secure;
	Oppbuf oppbuf;
	struct openpromio *opp2 = &(oppbuf.opp);
	char pwbuf[PW_SIZE + 2];
	int varlen1, varlen2;

	(void) strcpy(opp2->oprom_array, var);	/* safe; we know the name */
	if (getpropval(opp2) || opp2->oprom_size <= 0) {
		(void) printf("%s: data not available.\n", var);
		exit(1);
	}
	secure = strcmp(opp2->oprom_array, "none");

	/* Set up opp for mode */
	(void) strcpy(opp->oprom_array, var);	/* safe; we know the name */
	varlen1 = strlen(opp->oprom_array) + 1;
	if (strlen(val) > 32) {		/* 32 > [ "full", "command", "none" ] */
		(void) printf("Invalid security mode, mode unchanged.\n");
		exit(1);
	}
	(void) strcpy(opp->oprom_array + varlen1, val);
	opp->oprom_size = varlen1 + strlen(val);

	/* Set up opp2 for password */
	(void) strcpy(opp2->oprom_array, PASSWORD_PROPERTY);
	varlen2 = strlen(opp2->oprom_array) + 1;

	if ((strcmp(val, "full") == 0) || (strcmp(val, "command") == 0)) {
		if (! secure) {
			/* no password yet, get one */
			if (get_password(pwbuf, PW_SIZE)) {
				(void) strcpy(opp2->oprom_array + varlen2,
				    pwbuf);
				opp2->oprom_size = varlen2 + strlen(pwbuf);
				/* set password first */
				if (setpropval(opp2) || setpropval(opp))
					exit(1);
			} else
				exit(1);
		} else {
			if (setpropval(opp))
				exit(1);
		}
	} else if (strcmp(val, "none") == 0) {
		if (secure) {
			(void) memset(opp2->oprom_array + varlen2, '\0',
			    PW_SIZE);
			opp2->oprom_size = varlen2 + PW_SIZE;
			/* set mode first */
			if (setpropval(opp) || setpropval(opp2))
				exit(1);
		} else {
			if (setpropval(opp))
				exit(1);
		}
	} else {
		(void) printf("Invalid security mode, mode unchanged.\n");
		exit(1);
	}
}

/*
 * Set password.
 * We must be in a secure mode in order to do this.
 */
/* ARGSUSED */
static void
i_passwd(char *var, char *val, struct openpromio *opp)
{
	int secure;
	Oppbuf oppbuf;
	struct openpromio *opp2 = &(oppbuf.opp);
	char pwbuf[PW_SIZE + 2];
	int varlen;

	(void) strcpy(opp2->oprom_array, MODE_PROPERTY);
	if (getpropval(opp2) || opp2->oprom_size <= 0) {
		(void) printf("%s: data not available.\n", opp2->oprom_array);
		exit(1);
	}
	secure = strcmp(opp2->oprom_array, "none");

	if (!secure) {
		(void) printf("Not in secure mode\n");
		exit(1);
	}

	/* Set up opp for password */
	(void) strcpy(opp->oprom_array, var);	/* Safe; We know the name */
	varlen = strlen(opp->oprom_array) + 1;

	if (get_password(pwbuf, PW_SIZE)) {
		(void) strcpy(opp->oprom_array + varlen, pwbuf); /* Bounded */
		opp->oprom_size = varlen + strlen(pwbuf);
		if (setpropval(opp))
			exit(1);
	} else
		exit(1);
}

/* ARGSUSED */
static void
o_passwd(char *var, char *val)
{
	/* Don't print the password */
}

static int
get_password(char *pw_dest, int pwsize)
{
	int insist = 0, ok, flags;
	int c, pwlen;
	char *p;
	static char pwbuf[256];
	char *pasword = NULL;

tryagain:
	(void) printf("Changing PROM password:\n");
	if ((pasword = getpass("New password:")) == NULL) {
		exit(_error(NO_PERROR, "failed to get password"));
	}
	(void) strcpy(pwbuf, pasword);
	pwlen = strlen(pwbuf);
	if (pwlen == 0) {
		(void) printf("Password unchanged.\n");
		return (0);
	}
	/*
	 * Insure password is of reasonable length and
	 * composition.  If we really wanted to make things
	 * sticky, we could check the dictionary for common
	 * words, but then things would really be slow.
	 */
	ok = 0;
	flags = 0;
	p = pwbuf;
	while ((c = *p++) != 0) {
		if (c >= 'a' && c <= 'z')
			flags |= 2;
		else if (c >= 'A' && c <= 'Z')
			flags |= 4;
		else if (c >= '0' && c <= '9')
			flags |= 1;
		else
			flags |= 8;
	}
	if (flags >= 7 && pwlen >= 4)
		ok = 1;
	if ((flags == 2 || flags == 4) && pwlen >= 6)
		ok = 1;
	if ((flags == 3 || flags == 5 || flags == 6) && pwlen >= 5)
		ok = 1;
	if (!ok && insist < 2) {
	(void) printf("Please use %s.\n", flags == 1 ?
	    "at least one non-numeric character" : "a longer password");
		insist++;
		goto tryagain;
	}
	if (strcmp(pwbuf, getpass("Retype new password:")) != 0) {
		(void) printf("Mismatch - password unchanged.\n");
		return (0);
	}
	(void) strncpy(pw_dest, pwbuf, pwsize);
	return (1);
}
