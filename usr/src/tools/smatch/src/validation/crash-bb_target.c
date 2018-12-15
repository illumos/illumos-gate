a() {
  &&b

/*
 * check-name: crash bb_target
 * check-command: test-linearize $file
 *
 * check-error-ignore
 * check-output-ignore
 */
