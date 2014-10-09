/* krb5context.c --- Kerberos 5 security context self tests.
 * Copyright (C) 2003-2014 Simon Josefsson
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

/* Get Shishi prototypes. */
#include <shishi.h>

#include "utils.c"

static void
display_status_1 (const char *m, OM_uint32 code, int type)
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
	printf ("GSS-API display_status failed on code %d type %d\n",
		code, type);
      else
	{
	  printf ("GSS-API error %s (%s): %.*s\n",
		  m, type == GSS_C_GSS_CODE ? "major" : "minor",
		  (int) msg.length, (char *) msg.value);

	  gss_release_buffer (&min_stat, &msg);
	}
    }
  while (!GSS_ERROR (maj_stat) && msg_ctx);
}

static void
display_status (const char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
  display_status_1 (msg, maj_stat, GSS_C_GSS_CODE);
  display_status_1 (msg, min_stat, GSS_C_MECH_CODE);
}

int
main (int argc, char *argv[])
{
  gss_uint32 maj_stat, min_stat, ret_flags, time_rec;
  gss_buffer_desc bufdesc, bufdesc2;
  gss_name_t servername = GSS_C_NO_NAME, name;
  gss_ctx_id_t cctx = GSS_C_NO_CONTEXT;
  gss_ctx_id_t sctx = GSS_C_NO_CONTEXT;
  gss_cred_id_t server_creds;
  Shishi *handle;
  size_t i;
  struct gss_channel_bindings_struct cb;

  memset (&cb, 0, sizeof (cb));
  cb.application_data.length = 3;
  cb.application_data.value = (char *) "hej";

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

  handle = shishi ();

  /* Name of service. */

  bufdesc.value = (char *) "host@latte.josefsson.org";
  bufdesc.length = strlen (bufdesc.value);

  maj_stat = gss_import_name (&min_stat, &bufdesc,
			      GSS_C_NT_HOSTBASED_SERVICE, &servername);
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
	  /* Default OID, channel bindings. */
	  maj_stat = gss_init_sec_context (&min_stat,
					   GSS_C_NO_CREDENTIAL,
					   &cctx,
					   servername,
					   GSS_C_NO_OID,
					   GSS_C_MUTUAL_FLAG |
					   GSS_C_REPLAY_FLAG |
					   GSS_C_SEQUENCE_FLAG,
					   0,
					   &cb,
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
			    GSS_C_CONF_FLAG |
			    GSS_C_SEQUENCE_FLAG | GSS_C_PROT_READY_FLAG))
	    fail ("loop 2 ret_flags failure (%d)\n", ret_flags);
	  if (maj_stat != GSS_S_COMPLETE)
	    fail ("loop 1 init failure\n");
	  break;

	default:
	  fail ("default?!\n");
	  break;
	}
      if (GSS_ERROR (maj_stat))
	{
	  fail ("gss_accept_sec_context failure\n");
	  display_status ("accept_sec_context", maj_stat, min_stat);
	}

      if (debug)
	{
	  char *p = bufdesc2.value;
	  Shishi_asn1 apreq = shishi_der2asn1_apreq (handle,
						     p + 17,
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
					     &ret_flags, &time_rec, NULL);
	  if (ret_flags != (GSS_C_MUTUAL_FLAG |
			    /* XXX GSS_C_REPLAY_FLAG |
			       GSS_C_SEQUENCE_FLAG | */
			    GSS_C_PROT_READY_FLAG))
	    fail ("loop 0 accept flag failure (%d)\n", ret_flags);
	  break;

	case 1:
	  maj_stat = gss_accept_sec_context (&min_stat,
					     &sctx,
					     server_creds,
					     &bufdesc2,
					     &cb,
					     &name,
					     NULL,
					     &bufdesc,
					     &ret_flags, &time_rec, NULL);
	  break;

	case 2:
	  maj_stat = gss_accept_sec_context (&min_stat,
					     &sctx,
					     server_creds,
					     &bufdesc2,
					     GSS_C_NO_CHANNEL_BINDINGS,
					     &name,
					     NULL,
					     &bufdesc,
					     &ret_flags, &time_rec, NULL);
	  break;
	default:
	  fail ("default?!\n");
	  break;
	}
      if (GSS_ERROR (maj_stat))
	{
	  fail ("gss_accept_sec_context failure\n");
	  display_status ("accept_sec_context", maj_stat, min_stat);
	}

      if (debug)
	{
	  char *p = bufdesc2.value;
	  Shishi_asn1 aprep =
	    shishi_der2asn1_aprep (handle, p + 15, bufdesc.length - 15);
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
			    GSS_C_SEQUENCE_FLAG | GSS_C_PROT_READY_FLAG))
	    fail ("loop 1 ret_flags failure (%d)\n", ret_flags);
	  break;

	  /* No case 2. */

	default:
	  break;
	}
      if (GSS_ERROR (maj_stat))
	{
	  fail ("gss_init_sec_context failure (2)\n");
	  display_status ("init_sec_context", maj_stat, min_stat);
	}

      {
	gss_buffer_desc pt, pt2, ct;
	int conf_state;
	gss_qop_t qop_state;

	pt.value = (char *) "foo";
	pt.length = strlen (pt.value) + 1;
	maj_stat = gss_wrap (&min_stat, cctx, 0, 0, &pt, &conf_state, &ct);
	if (GSS_ERROR (maj_stat))
	  {
	    fail ("client gss_wrap failure\n");
	    display_status ("client wrap", maj_stat, min_stat);
	  }

	maj_stat = gss_unwrap (&min_stat, sctx,
			       &ct, &pt2, &conf_state, &qop_state);
	if (GSS_ERROR (maj_stat))
	  {
	    fail ("server gss_unwrap failure\n");
	    display_status ("client wrap", maj_stat, min_stat);
	  }

	if (pt.length != pt2.length
	    || memcmp (pt2.value, pt.value, pt.length) != 0)
	  fail ("wrap+unwrap failed (%d, %d, %.*s)\n",
		(int) pt.length, (int) pt2.length, (int) pt2.length,
		(char *) pt2.value);

	gss_release_buffer (&min_stat, &ct);
	gss_release_buffer (&min_stat, &pt2);
      }

      maj_stat = gss_delete_sec_context (&min_stat, &cctx, GSS_C_NO_BUFFER);
      if (GSS_ERROR (maj_stat))
	{
	  fail ("client gss_delete_sec_context failure\n");
	  display_status ("client delete_sec_context", maj_stat, min_stat);
	}

      maj_stat = gss_delete_sec_context (&min_stat, &sctx, GSS_C_NO_BUFFER);
      if (GSS_ERROR (maj_stat))
	{
	  fail ("server gss_delete_sec_context failure\n");
	  display_status ("server delete_sec_context", maj_stat, min_stat);
	}

      success ("loop %d ok\n", (int) i);
    }

  /* Clean up. */

  maj_stat = gss_release_cred (&min_stat, &server_creds);
  if (GSS_ERROR (maj_stat))
    {
      fail ("gss_release_cred");
      display_status ("release credentials", maj_stat, min_stat);
    }

  maj_stat = gss_release_name (&min_stat, &servername);
  if (GSS_ERROR (maj_stat))
    {
      fail ("gss_release_name failure\n");
      display_status ("gss_release_name", maj_stat, min_stat);
    }

  shishi_done (handle);

  /* We're done. */

  if (debug)
    printf ("Kerberos 5 security context self tests done with %d errors\n",
	    error_count);

  return error_count ? 1 : 0;
}
