/* krb5context.c --- Kerberos 5 security context self tests.
 * Copyright (C) 2003, 2004  Simon Josefsson
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

/* i18n. */
#ifdef HAVE_LOCALE_H
# include <locale.h>
#else
# define setlocale(Category, Locale)	/* empty */
#endif
#include <gettext.h>

/* Get GSS prototypes. */
#include "api.h"
#include "ext.h"
#include "krb5.h"

/* Get Shishi prototypes. */
#include <shishi.h>

static int verbose = 0;
static int debug = 0;
static int error_count = 0;
static int break_on_error = 0;

static void
fail (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  vfprintf (stderr, format, arg_ptr);
  va_end (arg_ptr);
  error_count++;
  if (break_on_error)
    exit (1);
}

static void
success (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  if (verbose)
    vfprintf (stdout, format, arg_ptr);
  va_end (arg_ptr);
}

static void
display_status_1 (char *m, OM_uint32 code, int type)
{
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc msg;
  OM_uint32 msg_ctx;

  msg_ctx = 0;
  do
    {
      maj_stat = gss_display_status (&min_stat, code,
				     type, GSS_C_NO_OID, &msg_ctx, &msg);
      if (GSS_ERROR (maj_stat))
	{
	  asprintf ((char**)&msg.value, "code %d", code);
	  msg.length = strlen (msg.value);
	}

      printf ("GSS-API error %s (%s): %.*s\n",
	      m, type == GSS_C_GSS_CODE ? "major" : "minor",
	      (int) msg.length, (char *) msg.value);

      if (GSS_ERROR (maj_stat))
	free (msg.value);
      else
	gss_release_buffer (&min_stat, &msg);
    }
  while (!GSS_ERROR (maj_stat) && msg_ctx);
}

static void
display_status (char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
  display_status_1 (msg, maj_stat, GSS_C_GSS_CODE);
  display_status_1 (msg, min_stat, GSS_C_MECH_CODE);
}

int
main (int argc, char *argv[])
{
  gss_uint32 maj_stat, min_stat, msgctx, ret_flags, time_rec;
  gss_buffer_desc bufdesc, bufdesc2;
  gss_name_t servername = GSS_C_NO_NAME, name;
  gss_OID_set oids;
  gss_ctx_id_t cctx = GSS_C_NO_CONTEXT;
  gss_ctx_id_t sctx = GSS_C_NO_CONTEXT;
  gss_cred_id_t cred_handle, server_creds;
  Shishi * handle;
  size_t i;

  setlocale (LC_ALL, "");
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

  handle = shishi ();

  /* Name of service. */

  bufdesc.value = "host@latte.josefsson.org";
  bufdesc.length = strlen (bufdesc.value);

  maj_stat = gss_import_name (&min_stat, &bufdesc,
			      GSS_C_NT_HOSTBASED_SERVICE,
			      &servername);
  if (GSS_ERROR (maj_stat))
    fail ("gss_import_name (host/server)\n");

  /* Get credential, for server. */

  maj_stat = gss_acquire_cred (&min_stat, servername, 0,
			       GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
			       &server_creds, NULL, NULL);
  if (GSS_ERROR (maj_stat))
    {
      fail ("gss_acquire_cred");
      display_status ("acquire credentials", maj_stat, min_stat);
    }

  for (i = 0; i < 3; i++)
    {
      /* Start client. */

      switch (i)
	{
	case 0:
	  maj_stat = gss_init_sec_context (&min_stat,
					   GSS_C_NO_CREDENTIAL,
					   &cctx,
					   servername,
					   GSS_KRB5,
					   GSS_C_MUTUAL_FLAG |
					   GSS_C_REPLAY_FLAG |
					   GSS_C_SEQUENCE_FLAG,
					   0,
					   GSS_C_NO_CHANNEL_BINDINGS,
					   GSS_C_NO_BUFFER, NULL,
					   &bufdesc2, NULL, NULL);
	  if (maj_stat != GSS_S_CONTINUE_NEEDED)
	    fail ("loop 0 init failure\n");
	  break;

	case 1:
	  /* Default OID. */
	  maj_stat = gss_init_sec_context (&min_stat,
					   GSS_C_NO_CREDENTIAL,
					   &cctx,
					   servername,
					   GSS_C_NO_OID,
					   GSS_C_MUTUAL_FLAG |
					   GSS_C_REPLAY_FLAG |
					   GSS_C_SEQUENCE_FLAG,
					   0,
					   GSS_C_NO_CHANNEL_BINDINGS,
					   GSS_C_NO_BUFFER, NULL,
					   &bufdesc2, NULL, NULL);
	  if (maj_stat != GSS_S_CONTINUE_NEEDED)
	    fail ("loop 0 init failure\n");
	  break;

	case 2:
	  /* No mutual authentication. */
	  maj_stat = gss_init_sec_context (&min_stat,
					   GSS_C_NO_CREDENTIAL,
					   &cctx,
					   servername,
					   GSS_KRB5,
					   GSS_C_REPLAY_FLAG |
					   GSS_C_CONF_FLAG |
					   GSS_C_SEQUENCE_FLAG,
					   0,
					   GSS_C_NO_CHANNEL_BINDINGS,
					   GSS_C_NO_BUFFER, NULL,
					   &bufdesc2, &ret_flags, NULL);
	  if (ret_flags != (GSS_C_REPLAY_FLAG |
			    GSS_C_CONF_FLAG|
			    GSS_C_SEQUENCE_FLAG|
			    GSS_C_PROT_READY_FLAG))
	    fail ("loop 2 ret_flags failure (%d)\n", ret_flags);
	  if (maj_stat != GSS_S_COMPLETE)
	    fail ("loop 1 init failure\n");
	  break;
	}
      if (GSS_ERROR (maj_stat))
	{
	  fail ("gss_accept_sec_context failure\n");
	  display_status ("accept_sec_context", maj_stat, min_stat);
	}

      if (debug)
	{
	  Shishi_asn1 apreq = shishi_der2asn1_apreq (handle, bufdesc2.value + 17,
						     bufdesc2.length - 17);
	  printf ("\nClient AP-REQ:\n\n");
	  shishi_apreq_print (handle, stdout, apreq);
	}

      /* Start server. */

      switch (i)
	{
	case 0:
	  maj_stat = gss_accept_sec_context (&min_stat,
					     &sctx,
					     server_creds,
					     &bufdesc2,
					     GSS_C_NO_CHANNEL_BINDINGS,
					     &name,
					     NULL,
					     &bufdesc,
					     &ret_flags,
					     &time_rec,
					     NULL);
	  if (ret_flags != (GSS_C_MUTUAL_FLAG |
			    /* XXX GSS_C_REPLAY_FLAG |
			       GSS_C_SEQUENCE_FLAG | */
			    GSS_C_PROT_READY_FLAG))
	    fail ("loop 0 accept flag failure (%d)\n", ret_flags);
	  break;

	default:
	  maj_stat = gss_accept_sec_context (&min_stat,
					     &sctx,
					     server_creds,
					     &bufdesc2,
					     GSS_C_NO_CHANNEL_BINDINGS,
					     &name,
					     NULL,
					     &bufdesc,
					     &ret_flags,
					     &time_rec,
					     NULL);
	  break;
	}
      if (GSS_ERROR (maj_stat))
	{
	  fail ("gss_accept_sec_context failure\n");
	  display_status ("accept_sec_context", maj_stat, min_stat);
	}

      if (debug)
	{
	  Shishi_asn1 aprep = shishi_der2asn1_aprep (handle, bufdesc.value + 15,
						     bufdesc.length - 15);
	  printf ("\nServer AP-REP:\n\n");
	  shishi_aprep_print (handle, stdout, aprep);
	}

      switch (i)
	{
	case 0:
	  maj_stat = gss_init_sec_context (&min_stat,
					   GSS_C_NO_CREDENTIAL,
					   &cctx,
					   servername,
					   GSS_KRB5,
					   GSS_C_MUTUAL_FLAG |
					   GSS_C_REPLAY_FLAG |
					   GSS_C_SEQUENCE_FLAG,
					   0,
					   GSS_C_NO_CHANNEL_BINDINGS,
					   &bufdesc, NULL,
					   &bufdesc2, NULL, NULL);
	  break;

	case 1:
	  /* Check ret_flags. */
	  maj_stat = gss_init_sec_context (&min_stat,
					   GSS_C_NO_CREDENTIAL,
					   &cctx,
					   servername,
					   GSS_KRB5,
					   GSS_C_MUTUAL_FLAG |
					   GSS_C_REPLAY_FLAG |
					   GSS_C_SEQUENCE_FLAG,
					   0,
					   GSS_C_NO_CHANNEL_BINDINGS,
					   &bufdesc, NULL,
					   &bufdesc2, &ret_flags, &time_rec);
	  if (ret_flags != (GSS_C_MUTUAL_FLAG |
			    GSS_C_REPLAY_FLAG |
			    GSS_C_SEQUENCE_FLAG|
			    GSS_C_PROT_READY_FLAG))
	    fail ("loop 1 ret_flags failure (%d)\n", ret_flags);
	  break;

	  /* No case 2. */
	}
      if (GSS_ERROR (maj_stat))
	{
	  fail ("gss_init_sec_context failure (2)\n");
	  display_status ("init_sec_context", maj_stat, min_stat);
	}

      maj_stat = gss_delete_sec_context (&min_stat, &cctx, GSS_C_NO_BUFFER);
      if (GSS_ERROR(maj_stat))
	{
	  fail ("client gss_delete_sec_context failure\n");
	  display_status ("client delete_sec_context", maj_stat, min_stat);
	}

      maj_stat = gss_delete_sec_context (&min_stat, &sctx, GSS_C_NO_BUFFER);
      if (GSS_ERROR(maj_stat))
	{
	  fail ("server gss_delete_sec_context failure\n");
	  display_status ("server delete_sec_context", maj_stat, min_stat);
	}

      success ("loop %d ok\n", i);
    }

  /* Clean up. */

  maj_stat = gss_release_cred (&min_stat, &server_creds);
  if (GSS_ERROR (maj_stat))
    {
      fail ("gss_release_cred");
      display_status ("release credentials", maj_stat, min_stat);
    }

  maj_stat = gss_release_name (&min_stat, &servername);
  if (GSS_ERROR(maj_stat))
    {
      fail ("gss_release_name failure\n");
      display_status ("gss_release_name", maj_stat, min_stat);
    }

  shishi_done (handle);

  /* We're done. */

  if (verbose)
    printf ("Kerberos 5 security context self tests done with %d errors\n",
	    error_count);

  return error_count ? 1 : 0;
}
