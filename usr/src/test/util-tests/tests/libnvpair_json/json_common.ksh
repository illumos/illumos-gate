#!/bin/ksh

function complete {
  if [[ "${PRINT_OUTPUT}" ]]; then
    printf "%s\n" "${OUTPUT}"
    exit 0
  elif [[ "${OUTPUT}" == "${BASELINE}" ]]; then
    printf "TEST PASS: %s\n" "$(basename $0)"
    exit 0
  else
    printf "TEST FAIL: %s\n" "$(basename $0)"
    printf "EXPECTED: %s\n" "${BASELINE}"
    printf "ACTUAL:   %s\n" "${OUTPUT}"
    exit 1
  fi
}
