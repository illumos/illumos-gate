/*
 * Test MS-CHAPv1 library code.
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Originally from the README.MSCHAP80 file written by:
 *	Eric Rosenquist          rosenqui@strataware.com
 *	(updated by Paul Mackerras)
 *	(updated by Al Longyear)
 *	(updated by Farrell Woods)
 */

#include <stdio.h>

#include "pppd.h"
#include "chap.h"
#include "chap_ms.h"

static void
show_response(chap_state *cstate, const char *str)
{
    int i;

    printf("%s -- %d bytes:", str, cstate->resp_length);

    for (i = 0; i < cstate->resp_length; i++) {
        if (i % 8 == 0)
            putchar('\n');
        printf("%02X ", (unsigned int)cstate->response[i]);
    }

    putchar('\n');
}

int main(argc, argv)
    int     argc;
    char    *argv[];
{
    u_char          challenge[8];
    int             challengeInt[sizeof(challenge)];
    chap_state      cstate;
    int             i;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <16-hexchar challenge> <password>\n",
        argv[0]); exit(1);
    }

    sscanf(argv[1], "%2x%2x%2x%2x%2x%2x%2x%2x",
           challengeInt + 0, challengeInt + 1, challengeInt + 2,
           challengeInt + 3, challengeInt + 4, challengeInt + 5,
           challengeInt + 6, challengeInt + 7);

    for (i = 0; i < sizeof(challenge); i++)
        challenge[i] = (u_char)challengeInt[i];

    BZERO(&cstate, sizeof(cstate));
    ChapMS(&cstate, challenge, sizeof(challenge), argv[2], strlen(argv[2]));
#ifdef MSLANMAN
    show_response(&cstate, "MS-CHAPv1 with LAN Manager");
#else
    show_response(&cstate, "MS-CHAPv1");
#endif

    cstate.chal_len = sizeof(challenge);
    BCOPY(challenge, cstate.challenge, cstate.chal_len);
    if (!ChapMSValidate(&cstate, cstate.response, cstate.resp_length,
	argv[2], strlen(argv[2])))
	printf("Cannot validate own MS-CHAPv1 response.\n");

#ifdef MSLANMAN
    cstate.response[MS_CHAP_RESPONSE_LEN-1] = '\0';
    if (!ChapMSValidate(&cstate, cstate.response, cstate.resp_length,
	argv[2], strlen(argv[2])))
	printf("Cannot validate own LAN Manager response.\n");
#endif

#ifdef CHAPMSV2
    cstate.resp_name = "joe user";
    ChapMSv2(&cstate, cstate.challenge, 16, argv[2], strlen(argv[2]));
    show_response(&cstate, "MS-CHAPv2");
    if (!ChapMSv2Validate(&cstate, cstate.resp_name, cstate.response,
	cstate.resp_length, argv[2], strlen(argv[2])))
	printf("Cannot validate own MS-CHAPv2 response.\n");
#endif

    return (0);
}
