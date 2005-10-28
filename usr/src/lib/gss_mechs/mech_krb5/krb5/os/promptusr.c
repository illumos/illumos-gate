#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * promptusr.c --- prompt user for input/output
 */

#include <k5-int.h>
#if !defined(_WIN32)

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <termios.h>
#include <signal.h>
#include <setjmp.h>

typedef struct _krb5_uio {
    krb5_magic		magic;
    int 		flags;
    char *		prompt;
    char *		response;
    struct _krb5_uio	*next;
} *krb5_uio;

#define KRB5_UIO_GETRESPONSE	0x0001
#define KRB5_UIO_ECHORESPONSE	0x0002
#define KRB5_UIO_FREE_PROMPT	0x0004

static jmp_buf pwd_jump;

/*ARGSUSED*/
static krb5_sigtype
intr_routine(int signo)
{
    longjmp(pwd_jump, 1);
    /*NOTREACHED*/
}

/*ARGSUSED*/
krb5_error_code
krb5_os_get_tty_uio(krb5_context context, krb5_uio uio)
{
    volatile krb5_error_code 	retval;
    krb5_sigtype	(*volatile ointrfunc)();
    krb5_uio		p;
    struct termios 	echo_control, save_control;
    int 		fd;
    char		read_string[BUFSIZ];
    char		*cp;
    int			ch;

    /* get the file descriptor associated with stdin */
    fd=fileno(stdin);

    if (tcgetattr(fd, &echo_control) == -1)
	return errno;

    save_control = echo_control;
    echo_control.c_lflag &= ~(ECHO|ECHONL);

    if (setjmp(pwd_jump)) {
	retval = KRB5_LIBOS_PWDINTR; 	/* we were interrupted... */
	goto cleanup;
    }
    /* save intrfunc */
    ointrfunc = signal(SIGINT, intr_routine);
    
    for (p = uio; p; p = p->next) {
	if (p->prompt) {
	    fputs(p->prompt, stdout);
	    fflush(stdout);
	}
	if ((p->flags & KRB5_UIO_GETRESPONSE) == 0)
	    continue;

	if ((p->flags & KRB5_UIO_ECHORESPONSE) == 0) 
	    if (tcsetattr(fd, TCSANOW, &echo_control) == -1)
		return errno;

	if (fgets(read_string, sizeof(read_string), stdin) == NULL) {
	    (void) putchar('\n');
	    retval = KRB5_LIBOS_CANTREADPWD;
	    goto cleanup;
	}
	
	/* replace newline with null */
	if ((cp = strchr(read_string, '\n')))
	    *cp = '\0';
	else /* flush rest of input line */
	    do {
		ch = getchar();
	    } while (ch != EOF && ch != '\n');
	read_string[sizeof(read_string)-1] = 0;

	if ((p->response = malloc(strlen(read_string)+1)) == NULL) {
	    errno = ENOMEM;
	    goto cleanup;
	}
	strcpy(p->response, read_string);

	if ((p->flags & KRB5_UIO_ECHORESPONSE) == 0) {
	    (void) putchar('\n');
	    if (tcsetattr(fd, TCSANOW, &save_control) == -1) {
		retval = errno;
		goto cleanup;
	    }
	}
    }
    retval = 0;
    
 cleanup:
    (void) signal(SIGINT, ointrfunc);
    if (retval) {
	for (p = uio; p; p = p->next) {
	    if (p->response) {
		memset(p->response, 0, strlen(p->response));
		free(p->response);
		p->response = 0;
	    }
	}
    }
    memset(read_string, 0, sizeof(read_string));
    tcsetattr(fd, TCSANOW, &save_control);
    return retval;
}

/*ARGSUSED*/
void
krb5_free_uio(krb5_context context, krb5_uio uio)
{
    krb5_uio		p, next;

    for (p = uio; p; p = next) {
	next = p->next;
	if (p->prompt && (p->flags & KRB5_UIO_FREE_PROMPT))
	    free(p->prompt);
	if (p->response)
	    free(p->response);
	free(p);
    }
}

#ifdef TEST_DRIVER

struct _krb5_uio uio_a = { 0, KRB5_UIO_GETRESPONSE, "Password 1: " };
struct _krb5_uio uio_b = { 0, KRB5_UIO_GETRESPONSE |
			       KRB5_UIO_ECHORESPONSE, "Password 2: " };
struct _krb5_uio uio_c = { 0, KRB5_UIO_GETRESPONSE, "Password 3: " };


void
main(int argc, char **argv)
{
    uio_a.next = &uio_b;
    uio_b.next = &uio_c;

    krb5_os_get_tty_uio(0, &uio_a);
    exit(0);
}

#endif
	
#endif /* !_MSODS */
