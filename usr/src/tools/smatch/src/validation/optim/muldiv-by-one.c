typedef	unsigned int ui;
typedef	         int si;

si smul1(si a) {  return a * 1; }
ui umul1(ui a) {  return a * 1; }
si sdiv1(si a) {  return a / 1; }
ui udiv1(ui a) {  return a / 1; }
si smod1(si a) {  return a % 1; }
ui umod1(ui a) {  return a % 1; }

/*
 * check-name: muldiv-by-one
 * check-command: test-linearize -Wno-decl $file
 * check-output-ignore
 *
 * check-output-excludes: mul[us]\\.
 * check-output-excludes: div[us]\\.
 * check-output-excludes: mod[us]\\.
 */
