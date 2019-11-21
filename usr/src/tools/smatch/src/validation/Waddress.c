extern int fun(void);
extern int arr[];
extern int var;

int test_address(int arg, int ptr[])
{

	if (fun())	return -1;
	if (var)	return -1;
	if (arg)	return -1;
	if (ptr)	return -1;

lab:
	if (arr)	return 1;
	if (&arr)	return 1;
	if (fun)	return 1;
	if (&fun)	return 1;
	if (*fun)	return 1;
	if (&var)	return 1;
	if (&arg)	return 1;
	if (&&lab)	return 1;

	return -1;
}

int test_address_not(int arg, int ptr[])
{

	if (!fun())	return -1;
	if (!var)	return -1;
	if (!arg)	return -1;
	if (!ptr)	return -1;

lab:
	if (!arr)	return 0;
	if (!&arr)	return 0;
	if (!fun)	return 0;
	if (!&fun)	return 0;
	if (!*fun)	return 0;
	if (!&var)	return 0;
	if (!&arg)	return 0;
	if (!&&lab)	return 0;

	return -1;
}

int test_address_cmp(int arg, int ptr[])
{
	if (fun() == 0)	return -1;
	if (0 == fun())	return -1;
	if (var == 0)	return -1;
	if (0 == var)	return -1;
	if (arg == 0)	return -1;
	if (0 == arg)	return -1;
	if (ptr == 0)	return -1;
	if (0 == ptr)	return -1;

lab:
	if (arr == 0)	return 0;
	if (0 == arr)	return 0;
	if (&arr == 0)	return 0;
	if (0 == &arr)	return 0;
	if (fun == 0)	return 0;
	if (0 == fun)	return 0;
	if (&fun == 0)	return 0;
	if (0 == &fun)	return 0;
	if (*fun == 0)	return 0;
	if (0 == *fun)	return 0;
	if (&var == 0)	return 0;
	if (0 == &var)	return 0;
	if (&arg == 0)	return 0;
	if (0 == &arg)	return 0;
	if (&&lab == 0)	return 0;
	if (0 == &&lab)	return 0;

	return -1;
}

/*
 * check-name: Waddress
 * check-command: sparse -Wno-decl -Wno-non-pointer-null -Waddress $file
 * check-known-to-fail
 *
 * check-error-start
Waddress.c:14:13: warning: the address of an array will always evaluate as true
Waddress.c:15:14: warning: the address of an array will always evaluate as true
Waddress.c:16:13: warning: the address of a function will always evaluate as true
Waddress.c:17:14: warning: the address of a function will always evaluate as true
Waddress.c:18:13: warning: the address of a variable will always evaluate as true
Waddress.c:19:13: warning: the address of a variable will always evaluate as true
Waddress.c:20:13: warning: the address of a label will always evaluate as true
Waddress.c:34:13: warning: the address of an array will always evaluate as true
Waddress.c:35:13: warning: the address of an array will always evaluate as true
Waddress.c:36:13: warning: the address of a function will always evaluate as true
Waddress.c:37:13: warning: the address of a function will always evaluate as true
Waddress.c:38:13: warning: the address of a variable will always evaluate as true
Waddress.c:39:13: warning: the address of a variable will always evaluate as true
Waddress.c:40:13: warning: the address of a label will always evaluate as true
Waddress.c:57:13: warning: the address of an array will always evaluate as true
Waddress.c:58:13: warning: the address of an array will always evaluate as true
Waddress.c:59:13: warning: the address of an array will always evaluate as true
Waddress.c:60:13: warning: the address of an array will always evaluate as true
Waddress.c:61:13: warning: the address of a function will always evaluate as true
Waddress.c:62:13: warning: the address of a function will always evaluate as true
Waddress.c:63:13: warning: the address of a function will always evaluate as true
Waddress.c:64:13: warning: the address of a function will always evaluate as true
Waddress.c:65:13: warning: the address of a variable will always evaluate as true
Waddress.c:66:13: warning: the address of a variable will always evaluate as true
Waddress.c:67:13: warning: the address of a variable will always evaluate as true
Waddress.c:68:13: warning: the address of a variable will always evaluate as true
Waddress.c:69:13: warning: the address of a label will always evaluate as true
Waddress.c:70:13: warning: the address of a label will always evaluate as true
 * check-error-end
 */
