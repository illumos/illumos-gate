#define __user		__attribute__((address_space(1)))
#define __safe		__attribute__((safe))
#define __nocast	__attribute__((nocast))
#define __bitwise	__attribute__((bitwise))
#define __noderef	__attribute__((noderef))

int test(void)
{
	if ([int] != [int]) return 1;
	if (!([int] == [int])) return 1;

	if ([int] == [long]) return 1;
	if (!([int] != [long])) return 1;

	if ([int] == [unsigned int]) return 1;
	if (!([int] != [unsigned int])) return 1;

	if ([int] != [int]) return 1;
	if ([typeof(int)] != [int]) return 1;
	if ([int] != [typeof(int)]) return 1;
	if ([typeof(int)] != [typeof(int)]) return 1;

	if ([char] > [short]) return 1;
	if ([short] < [char]) return 1;
	if (!([char] <= [short])) return 1;
	if (!([short] >= [char])) return 1;

	if ([short] > [int]) return 1;
	if ([int] < [short]) return 1;
	if (!([short] <= [int])) return 1;
	if (!([int] >= [short])) return 1;

	if ([int] > [long]) return 1;
	if ([long] < [int]) return 1;
	if (!([int] <= [long])) return 1;
	if (!([long] >= [int])) return 1;

	if ([long] > [long long]) return 1;
	if ([long long] < [long]) return 1;
	if (!([long] <= [long long])) return 1;
	if (!([long long] >= [long])) return 1;

	if ([int *] != [int *]) return 1;
	if ([int *] == [void *]) return 1;

	// qualifiers are ignored
	if ([int] != [const int]) return 1;
	if ([int] != [volatile int]) return 1;

	// but others modifiers are significant
	if ([int] == [int __nocast]) return 1;
	if ([int] == [int __bitwise]) return 1;

	//
	if ([int *] == [const int *]) return 1;
	if ([int *] == [volatile int *]) return 1;
	if ([int *] == [int __user *]) return 1;
	if ([int *] == [int __safe *]) return 1;
	if ([int *] == [int __nocast *]) return 1;
	if ([int *] == [int __bitwise *]) return 1;
	if ([int *] == [int __noderef *]) return 1;

	return 0;
}

/*
 * check-name: type-as-first-class comparison
 * check-description: This test the sparse extension making
 *	types first class citizens which can be compared
 *	for equality (or size for <, >, <=, >=).
 *	See expand.c:compare_types().
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-contains: ret\\..*\\$0
 */
