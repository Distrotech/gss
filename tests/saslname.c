/* saslname.c --- Test of new SASL GS2 related GSS-API functions
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2009, 2010  Simon Josefsson
 *
 * This file is part of the Generic Security Service (GSS).
 *
 * GSS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GSS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GSS; if not, see http://www.gnu.org/licenses or write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA.
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

/* Get GSS prototypes. */
#include <gss.h>

#include "utils.c"

int
main (int argc, char *argv[])
{
  gss_uint32 maj_stat, min_stat;
  gss_buffer_desc bufdesc;
  gss_OID oid;

  do
    if (strcmp (argv[argc - 1], "-v") == 0 ||
	strcmp (argv[argc - 1], "--verbose") == 0)
      debug = 1;
    else if (strcmp (argv[argc - 1], "-b") == 0 ||
	     strcmp (argv[argc - 1], "--break-on-error") == 0)
      break_on_error = 1;
    else if (strcmp (argv[argc - 1], "-h") == 0 ||
	     strcmp (argv[argc - 1], "-?") == 0 ||
	     strcmp (argv[argc - 1], "--help") == 0)
      {
	printf ("Usage: %s [-vbh?] [--verbose] [--break-on-error] [--help]\n",
		argv[0]);
	return 1;
      }
  while (argc-- > 1);

  maj_stat = gss_inquire_mech_for_saslname (&min_stat, NULL, NULL);
  if (maj_stat == GSS_S_CALL_INACCESSIBLE_READ)
    success ("gss_inquire_mech_for_saslname (NULL, NULL) success\n");
  else
    fail ("gss_inquire_mech_for_saslname (NULL, NULL) failed (%d,%d)\n",
	  maj_stat, min_stat);

  bufdesc.value = NULL;
  bufdesc.length = 0;

  maj_stat = gss_inquire_mech_for_saslname (&min_stat, &bufdesc, NULL);
  if (maj_stat == GSS_S_BAD_MECH)
    success ("gss_inquire_mech_for_saslname (EMPTY, NULL) success\n");
  else
    fail ("gss_inquire_mech_for_saslname (EMPTY, NULL) failed (%d,%d)\n",
	  maj_stat, min_stat);

#ifdef USE_KERBEROS5
  bufdesc.length = 8;
  bufdesc.value = malloc (bufdesc.length);
  memcpy (bufdesc.value, "GS2-KRB5", bufdesc.length);

  maj_stat = gss_inquire_mech_for_saslname (&min_stat, &bufdesc, NULL);
  if (maj_stat == GSS_S_COMPLETE)
    success ("gss_inquire_mech_for_saslname (GS2-KRB5, NULL) success\n");
  else
    fail ("gss_inquire_mech_for_saslname (GS2-KRB5, NULL) failed (%d,%d)\n",
	  maj_stat, min_stat);

  maj_stat = gss_inquire_mech_for_saslname (&min_stat, &bufdesc, &oid);
  if (maj_stat == GSS_S_COMPLETE)
    success ("gss_inquire_mech_for_saslname (GS2-KRB5, OID) success\n");
  else
    fail ("gss_inquire_mech_for_saslname (GS2-KRB5, OID) failed (%d,%d)\n",
	  maj_stat, min_stat);

  if (oid != GSS_KRB5 || !gss_oid_equal (oid, GSS_KRB5))
    fail ("GS2-OID not Krb5?!\n");

  free (bufdesc.value);
#endif

  maj_stat = gss_inquire_saslname_for_mech (&min_stat, NULL, NULL, NULL, NULL);
  if (maj_stat == GSS_S_CALL_INACCESSIBLE_READ)
    success ("gss_inquire_saslname_for_mech (NULL) success\n");
  else
    fail ("gss_inquire_saslname_for_mech (NULL) failed (%d,%d)\n",
	  maj_stat, min_stat);

  maj_stat = gss_inquire_saslname_for_mech (&min_stat, GSS_C_NT_USER_NAME,
					    NULL, NULL, NULL);
  if (maj_stat == GSS_S_BAD_MECH)
    success ("gss_inquire_saslname_for_mech (NT_USER_NAME) success\n");
  else
    fail ("gss_inquire_saslname_for_mech (NT_USER_NAME) failed (%d,%d)\n",
	  maj_stat, min_stat);

#ifdef USE_KERBEROS5
  maj_stat = gss_inquire_saslname_for_mech (&min_stat, GSS_KRB5,
					    NULL, NULL, NULL);
  if (maj_stat == GSS_S_COMPLETE)
    success ("gss_inquire_saslname_for_mech (GSS-KRB5) success\n");
  else
    fail ("gss_inquire_saslname_for_mech (GSS-KRB5) failed (%d,%d)\n",
	  maj_stat, min_stat);

  bufdesc.value = NULL;
  bufdesc.length = 0;

  maj_stat = gss_inquire_saslname_for_mech (&min_stat, GSS_KRB5,
					    &bufdesc, NULL, NULL);
  if (maj_stat == GSS_S_COMPLETE)
    success ("gss_inquire_saslname_for_mech (GSS-KRB5) success: %.*s\n",
	     bufdesc.length, (char *) bufdesc.value);
  else
    fail ("gss_inquire_saslname_for_mech (GSS-KRB5) failed (%d,%d)\n",
	  maj_stat, min_stat);

  maj_stat = gss_release_buffer (&min_stat, &bufdesc);
  if (maj_stat == GSS_S_COMPLETE)
    success ("gss_release_buffer() OK\n");
  else
    fail ("gss_release_buffer() failed (%d,%d)\n", maj_stat, min_stat);

  maj_stat = gss_inquire_saslname_for_mech (&min_stat, GSS_KRB5,
					    NULL, &bufdesc, NULL);
  if (maj_stat == GSS_S_COMPLETE)
    success ("gss_inquire_saslname_for_mech (GSS-KRB5-2) success: %.*s\n",
	     bufdesc.length, (char *) bufdesc.value);
  else
    fail ("gss_inquire_saslname_for_mech (GSS-KRB5-2) failed (%d,%d)\n",
	  maj_stat, min_stat);

  maj_stat = gss_release_buffer (&min_stat, &bufdesc);
  if (maj_stat == GSS_S_COMPLETE)
    success ("gss_release_buffer() OK\n");
  else
    fail ("gss_release_buffer() failed (%d,%d)\n", maj_stat, min_stat);

  maj_stat = gss_inquire_saslname_for_mech (&min_stat, GSS_KRB5,
					    NULL, NULL, &bufdesc);
  if (maj_stat == GSS_S_COMPLETE)
    success ("gss_inquire_saslname_for_mech (GSS-KRB5-3) success: %.*s\n",
	     bufdesc.length, (char *) bufdesc.value);
  else
    fail ("gss_inquire_saslname_for_mech (GSS-KRB5-3) failed (%d,%d)\n",
	  maj_stat, min_stat);

  maj_stat = gss_release_buffer (&min_stat, &bufdesc);
  if (maj_stat == GSS_S_COMPLETE)
    success ("gss_release_buffer() OK\n");
  else
    fail ("gss_release_buffer() failed (%d,%d)\n", maj_stat, min_stat);
#endif

  if (debug)
    printf ("Basic self tests done with %d errors\n", error_count);

  return error_count ? 1 : 0;
}
