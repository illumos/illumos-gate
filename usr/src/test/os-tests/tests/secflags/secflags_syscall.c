#include <stdio.h>
#include <err.h>
#include <errno.h>

#include <sys/secflags.h>
#include <sys/syscall.h>

int
main(int argc, char **argv)
{
	int err = 0;
	secflagdelta_t act = {0};

	if ((err = syscall(SYS_psecflags, NULL, PSF_INHERIT, NULL)) != 0) {
		if (errno != EFAULT)
			warnx("attempt to set secflags with a NULL procset "
			    "set errno other than EFAULT (%d)", errno);
	} else {
		warnx("attempt to set secflags with a NULL procset succeeded");
	}

	if ((err = syscall(SYS_psecflags, (void*)0xdeadbeef,
	    PSF_INHERIT, NULL)) != 0) {
		if (errno != EFAULT)
			warnx("attempt to set secflags with a bad procset "
			    "set errno other than EFAULT (%d)", errno);
	} else {
		warnx("attempt to set secflags with a bad procset succeeded");
	}


	if ((err = psecflags(P_PID, P_MYID, PSF_INHERIT, NULL)) != 0) {
		if (errno != EFAULT)
			warnx("attempt to set secflags with a NULL "
			    "delta set errno to other than EFAULT (%d)",
			    errno);
	} else {
		warnx("attempt to set secflags with a NULL delta succeeded");
	}

	if ((err = psecflags(P_PID, P_MYID, PSF_INHERIT,
	    (void*)0xdeadbeef)) != 0) {
		if (errno != EFAULT)
			warnx("attempt to set secflags with a bad "
			    "delta set errno to other than EFAULT (%d)",
			    errno);
	} else {
		warnx("attempt to set secflags with a bad delta succeeded");
	}

	if ((err = psecflags(P_LWPID, P_MYID, PSF_INHERIT, &act)) != 0) {
		if (errno != EINVAL)
			warnx("attempt to set secflags of an lwpid set errno "
			    "to other than EINVAL (%d)", errno);
	} else {
		warnx("attempt to set secflags of an lwpid succeeded");
	}

	if ((err = psecflags(P_LWPID, P_MYID, PSF_EFFECTIVE, &act)) != 0) {
		if (errno != EINVAL)
			warnx("attempt to set effective secflags set errno "
			    "to other than EINVAL (%d)", errno);
	} else {
		warnx("attempt to set effective secflags succeeded");
	}

	return (0);
}
