float *f01(void* p)
{
	return p;
}

/*
 * check-name: fp-vs-ptrcast
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: fpcast
 * check-output-contains: ptrcast
 */
