/* krb5.c	Kerberos 5 GSS self tests.
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

int
main (int argc, char *argv[])
{
  char buffer[BUFSIZ];
  char buffer2[BUFSIZ];
  char *p, *q;
  int n, res;
  gss_uint32 maj_stat, min_stat;
  gss_buffer_desc buf, buf2;
  gss_ctx_id_t ctx;
  gss_name_t service;

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

  buf.value = "imap/mail1.nada.kth.se";
  buf.length = strlen(buf.value);

  maj_stat = gss_import_name (&min_stat, &buf, GSS_C_NT_HOSTBASED_SERVICE,
			      &service);
  if (maj_stat == GSS_S_COMPLETE)
    success("gss_import_name() OK\n");
  else
    fail("gss_import_name() failed (%d,%d)\n", maj_stat, min_stat);

  buf.length = 0;
  buf.value = NULL;
  buf2.length = 0;
  buf2.value = NULL;
  ctx = GSS_C_NO_CONTEXT;
  maj_stat = gss_init_sec_context (&min_stat,
				   GSS_C_NO_CREDENTIAL,
				   &ctx,
				   service,
				   GSS_C_NO_OID,
				   GSS_C_MUTUAL_FLAG |
				   GSS_C_REPLAY_FLAG |
				   GSS_C_SEQUENCE_FLAG,
				   0,
				   GSS_C_NO_CHANNEL_BINDINGS,
				   &buf, NULL, &buf2, NULL, NULL);
  if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
    fail("gss_init_sec_context() failed (%d,%d)\n", maj_stat, min_stat);

  if (verbose)
    printf ("Kerberos 5 self tests done with %d errors\n", error_count);

  return error_count ? 1 : 0;
}
