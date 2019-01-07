typedef	unsigned int ui;
typedef	         int si;

si smul0(si a) {  return a * 0; }
ui umul0(ui a) {  return a * 0; }

/*
 * check-name: muldiv-by-zero
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: mul[us]\\.
 */
