int foo(int *ptr, int i)
{
	int *p;

	switch (i - i) {		// will be optimized to 0
	case 0:
		return 0;
	case 1:				// will be optimized away
		p = ptr;
		do {			// will be an unreachable loop
			*p++ = 123;
		} while (--i);
		break;
	}

	return 1;
}

int bar(int *ptr, int i)
{
	int *p;

	switch (i - i) {		// will be optimized to 0
	case 0:
		return 0;
	case 1:				// will be optimized away
					// p is uninitialized
		do {			// will be an unreachable loop
			*p++ = 123;
		} while (--i);
		break;
	}

	return 1;
}

/*
 * check-name: crazy02-not-so.c
 * check-command: sparse -Wno-decl $file
 */
