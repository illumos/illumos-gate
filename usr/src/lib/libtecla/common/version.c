#include "libtecla.h"

/*.......................................................................
 * Return the version number of the tecla library.
 *
 * Input:
 *  major    int *   The major version number of the library
 *                   will be assigned to *major. This number is
 *                   only incremented when a change to the library is
 *                   made that breaks binary (shared library) and/or
 *                   compilation backwards compatibility.
 *  minor    int *   The minor version number of the library
 *                   will be assigned to *minor. This number is
 *                   incremented whenever new functions are added to
 *                   the public API.
 *  micro    int *   The micro version number of the library will be
 *                   assigned to *micro. This number is incremented
 *                   whenever internal changes are made that don't
 *                   change the public API, such as bug fixes and
 *                   performance enhancements.
 */
void libtecla_version(int *major, int *minor, int *micro)
{
  if(major)
    *major = TECLA_MAJOR_VER;
  if(minor)
    *minor = TECLA_MINOR_VER;
  if(micro)
    *micro = TECLA_MICRO_VER;
}
