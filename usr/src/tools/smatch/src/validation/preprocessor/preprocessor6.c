/* We used to get '##' wrong for the kernel.
 *
 * It could possibly be argued that the kernel usage is undefined (since the
 * different sides of the '##' are not proper tokens), but we try to do it
 * right anyway.
 *
 * We used to break up the "003d" into two tokens ('003' and 'd') and then put
 * the 'o' marker to mark the token 003 as an octal number, resulting in:
 *
 *	static char __vendorstr_o03 d [ ] __devinitdata = "Lockheed Martin-Marietta Corp";
 *
 * which didn't work, of course.
 */

#define __devinitdata __attribute__((section(".devinit")))

#define VENDOR( vendor, name ) \
	static char __vendorstr_##vendor[] __devinitdata = name;
VENDOR(003d,"Lockheed Martin-Marietta Corp")

/*
 * check-name: Preprocessor #6
 * check-command: sparse -E $file
 *
 * check-output-start

static char __vendorstr_003d[] __attribute__((section(".devinit"))) = "Lockheed Martin-Marietta Corp";
 * check-output-end
 */
