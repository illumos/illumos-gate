static void foo(void)
{
	asm("");
	asm volatile ("v");
	asm inline ("i");
	asm volatile inline ("vi");
	asm inline volatile ("iv");

	asm goto ("g" :::: label);
	asm volatile goto ("vg" :::: label);
	asm inline goto ("ig" :::: label);
	asm volatile inline goto ("vig" :::: label);
	asm inline volatile goto ("ivg" :::: label);

	asm goto volatile ("gv" :::: label);
	asm goto inline ("gi" :::: label);
	asm goto volatile inline ("gvi" :::: label);
	asm goto inline volatile ("giv" :::: label);
	asm volatile goto inline ("vgi" :::: label);
	asm inline goto volatile ("giv" :::: label);

	// warn on duplicates
	asm volatile volatile ("vv");
	asm inline inline ("ii");
	asm goto goto ("gg" :::: label);

	asm inline volatile inline ("ivi");
	asm inline goto inline ("igi" :::: label);
	asm goto inline goto ("gig" :::: label);
	asm goto volatile goto ("gvg" :::: label);
	asm volatile inline volatile ("viv");
	asm volatile goto volatile ("vgv" :::: label);

label:
	;
}

/*
 * check-name: asm-inline
 *
 * check-error-start
asm-inline.c:23:22: warning: duplicated asm modifier
asm-inline.c:24:20: warning: duplicated asm modifier
asm-inline.c:25:18: warning: duplicated asm modifier
asm-inline.c:27:29: warning: duplicated asm modifier
asm-inline.c:28:25: warning: duplicated asm modifier
asm-inline.c:29:25: warning: duplicated asm modifier
asm-inline.c:30:27: warning: duplicated asm modifier
asm-inline.c:31:29: warning: duplicated asm modifier
asm-inline.c:32:27: warning: duplicated asm modifier
 * check-error-end
 */
