/* basic.c	Basic GSS self tests.
 * Copyright (C) 2003  Simon Josefsson
 *
 * This file is part of the Generic Security Service (GSS).
 *
 * GSS is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GSS is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GSS; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

#include "utils.c"

const char *program_name = PACKAGE;

int
main (int argc, char *argv[])
{
  char buffer[BUFSIZ];
  char buffer2[BUFSIZ];
  char *p, *q;
  int n, res;
  gss_uint32 maj_stat, min_stat, msgctx;
  gss_buffer_desc bufdesc, bufdesc2;
  gss_name_t service;
  gss_OID_set oids;

#if HAVE_LOCALE_H
  setlocale (LC_ALL, "");
#endif
  bindtextdomain (PACKAGE, LOCALEDIR);

  do
    if (strcmp (argv[argc - 1], "-v") == 0 ||
	strcmp (argv[argc - 1], "--verbose") == 0)
      verbose = 1;
    else if (strcmp (argv[argc - 1], "-d") == 0 ||
	     strcmp (argv[argc - 1], "--debug") == 0)
      debug = 1;
    else if (strcmp (argv[argc - 1], "-b") == 0 ||
	     strcmp (argv[argc - 1], "--break-on-error") == 0)
      break_on_error = 1;
    else if (strcmp (argv[argc - 1], "-h") == 0 ||
	     strcmp (argv[argc - 1], "-?") == 0 ||
	     strcmp (argv[argc - 1], "--help") == 0)
      {
	printf ("Usage: %s [-vdbh?] [--verbose] [--debug] "
		"[--break-on-error] [--help]\n", argv[0]);
	return 1;
      }
  while (argc-- > 1);

  escapeprint (NULL, 0);
  hexprint (NULL, 0);
  binprint (NULL, 0);

  /* OID set tests */
  oids = GSS_C_NO_OID_SET;
  maj_stat = gss_create_empty_oid_set (&min_stat, &oids);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_create_empty_oid_set() OK\n");
  else
    fail("gss_create_empty_oid_set() failed (%d,%d)\n", maj_stat, min_stat);

  /* Test empty set */
  maj_stat = gss_test_oid_set_member (&min_stat, GSS_C_NT_USER_NAME, oids, &n);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    OID present in empty set => %d\n", n);

  if (!n)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  /* Add an OID */
  maj_stat = gss_add_oid_set_member (&min_stat, GSS_C_NT_USER_NAME, &oids);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_add_oid_set_member() OK\n");
  else
    fail("gss_add_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  /* Test set for added OID */
  maj_stat = gss_test_oid_set_member (&min_stat, GSS_C_NT_USER_NAME, oids, &n);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    OID present in set with the OID added to it => %d\n", n);

  if (n)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  /* Test set for another OID */
  maj_stat = gss_test_oid_set_member (&min_stat, GSS_C_NT_ANONYMOUS, oids, &n);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    Another OID present in set without the OID => %d\n", n);

  if (!n)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  /* Add another OID */
  maj_stat = gss_add_oid_set_member (&min_stat, GSS_C_NT_ANONYMOUS, &oids);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_add_oid_set_member() OK\n");
  else
    fail("gss_add_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  /* Test set for added OID */
  maj_stat = gss_test_oid_set_member (&min_stat, GSS_C_NT_ANONYMOUS, oids, &n);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    Another OID present in set with it added => %d\n", n);

  if (n)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  /* Test set for first OID */
  maj_stat = gss_test_oid_set_member (&min_stat, GSS_C_NT_USER_NAME, oids, &n);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    First OID present in set => %d\n", n);

  if (n)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  /* Check mechs */
  oids = GSS_C_NO_OID_SET;
  maj_stat = gss_indicate_mechs (&min_stat, &oids);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_indicate_mechs() OK\n");
  else
    fail("gss_indicate_mechs() failed (%d,%d)\n", maj_stat, min_stat);

#ifdef USE_KERBEROS5
  maj_stat = gss_test_oid_set_member (&min_stat, GSS_KRB5, oids, &n);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    kerberos5 supported => %d\n", n);

  if (n)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);
#endif

  maj_stat = gss_release_oid_set (&min_stat, &oids);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_release_oid_set() OK\n");
  else
    fail("gss_release_oid_set() failed (%d,%d)\n", maj_stat, min_stat);

#ifdef USE_KERBEROS5
  maj_stat = gss_inquire_names_for_mech (&min_stat, GSS_KRB5, &oids);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_inquire_names_for_mech() OK\n");
  else
    fail("gss_inquire_names_for_mech() failed (%d,%d)\n", maj_stat, min_stat);

  /* Check if KRB5 supports PRINCIPAL_NAME name type */
  maj_stat = gss_test_oid_set_member (&min_stat, GSS_KRB5_NT_PRINCIPAL_NAME,
				      oids, &n);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    kerberos5 supports PRINCIPAL_NAME name type => %d\n", n);

  if (n)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  /* Check if KRB5 supports HOSTBASED NAME name type */
  maj_stat = gss_test_oid_set_member (&min_stat, GSS_C_NT_HOSTBASED_SERVICE,
				      oids, &n);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    kerberos5 supports HOSTBASED_SERVICE name type => %d\n", n);

  if (n)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  /* Check if KRB5 supports ANONYMOUS name type */
  maj_stat = gss_test_oid_set_member (&min_stat, GSS_C_NT_ANONYMOUS, oids, &n);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    kerberos5 supports ANONYMOUS name type => %d\n", n);

  if (!n)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  maj_stat = gss_release_oid_set (&min_stat, &oids);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_release_oid_set() OK\n");
  else
    fail("gss_release_oid_set() failed (%d,%d)\n", maj_stat, min_stat);
#endif

  /* Check name */
  service = NULL;
  bufdesc.value = "imap@server.example.org@FOO";
  bufdesc.length = strlen(bufdesc.value);

  maj_stat = gss_import_name (&min_stat, &bufdesc, GSS_C_NT_HOSTBASED_SERVICE,
			      &service);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_import_name() OK\n");
  else
    fail("gss_import_name() failed (%d,%d)\n", maj_stat, min_stat);

  maj_stat = gss_display_name (&min_stat, service, &bufdesc2, NULL);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_display_name() OK\n");
  else
    fail("gss_display_name() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    display_name() => %d: %s\n", bufdesc2.length, bufdesc2.value);

#ifdef USE_KERBEROS5
  /* NB: "service" resused from previous test */
  maj_stat = gss_inquire_mechs_for_name (&min_stat, service, &oids);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_inquire_mechs_for_name() OK\n");
  else
    fail("gss_inquire_mechs_for_name() failed (%d,%d)\n", maj_stat, min_stat);

  /* Check GSS_C_NT_HOSTBASED_SERVICE name type is supported by KRB5 */
  maj_stat = gss_test_oid_set_member (&min_stat, GSS_KRB5, oids, &n);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    HOSTBASED_SERVICE supported by kerberos5 => %d\n", n);

  if (n)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  /* Dummy OID check */
  maj_stat = gss_test_oid_set_member (&min_stat, GSS_C_NT_ANONYMOUS,
				      oids, &n);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    Dummy oid supported by kerberos5 => %d\n", n);

  if (!n)
    success("gss_test_oid_set_member() OK\n");
  else
    fail("gss_test_oid_set_member() failed (%d,%d)\n", maj_stat, min_stat);

  maj_stat = gss_release_oid_set (&min_stat, &oids);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_release_oid_set() OK\n");
  else
    fail("gss_release_oid_set() failed (%d,%d)\n", maj_stat, min_stat);
#endif

  /* Check display_status */
  msgctx = 0;
  maj_stat = gss_display_status (&min_stat, GSS_S_COMPLETE, GSS_C_GSS_CODE,
				 GSS_C_NO_OID, &msgctx, &bufdesc);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_display_status() OK\n");
  else
    fail("gss_display_status() failed (%d,%d)\n", maj_stat, min_stat);

  if (debug)
    printf("    Display status for GSS_S_COMPLETE => %*s\n",
	   bufdesc.length, bufdesc.value);

  if (verbose)
    printf ("Name self tests done with %d errors\n", error_count);

  return error_count ? 1 : 0;
}
