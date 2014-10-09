/* gss.c --- Command line tool for GSS.
 * Copyright (C) 2004-2014 Simon Josefsson
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
#include <string.h>
#include <errno.h>

/* For gettext. */
#include <locale.h>
#include <gettext.h>
#define _(String) gettext (String)

/* Get GSS header. */
#include <gss.h>

/* Command line parameter parser via gengetopt. */
#include "gss_cmd.h"

/* Gnulib utils. */
#include "base64.h"
#include "error.h"
#include "progname.h"
#include "version-etc.h"

const char version_etc_copyright[] =
  /* Do *not* mark this string for translation.  %s is a copyright
     symbol suitable for this locale, and %d is the copyright
     year.  */
  "Copyright %s %d Simon Josefsson.";

/* This feature is available in gcc versions 2.5 and later.  */
#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
# define GSS_ATTR_NO_RETRUN
#else
# define GSS_ATTR_NO_RETRUN __attribute__ ((__noreturn__))
#endif

static void
usage (int status)
  GSS_ATTR_NO_RETRUN;

     static void usage (int status)
{
  if (status != EXIT_SUCCESS)
    fprintf (stderr, _("Try `%s --help' for more information.\n"),
	     program_name);
  else
    {
      printf (_("\
Usage: %s OPTIONS...\n\
"), program_name);
      fputs (_("\
Command line interface to GSS, used to explain error codes.\n\
\n\
"), stdout);
      fputs (_("\
Mandatory arguments to long options are mandatory for short options too.\n\
"), stdout);
      fputs (_("\
  -h, --help        Print help and exit.\n\
  -V, --version     Print version and exit.\n\
  -l, --list-mechanisms\n\
                    List information about supported mechanisms\n\
                    in a human readable format.\n\
  -m, --major=LONG  Describe a `major status' error code value.\n\
"), stdout);
      fputs (_("\
  -a, --accept-sec-context[=MECH]\n\
                    Accept a security context as server.\n\
                    If MECH is not specified, no credentials\n\
                    will be acquired.  Use \"*\" to use library\n\
                    default mechanism.\n\
  -i, --init-sec-context=MECH\n\
                    Initialize a security context as client.\n\
                    MECH is the SASL name of mechanism, use -l\n\
                    to list supported mechanisms.\n\
  -n, --server-name=SERVICE@HOSTNAME\n\
                    For -i and -a, set the name of the remote host.\n\
                    For example, \"imap@mail.example.com\".\n\
"), stdout);
      fputs (_("\
  -q, --quiet       Silent operation (default=off).\n\
"), stdout);
      emit_bug_reporting_address ();
    }
  exit (status);
}

static int
describe_major (unsigned int quiet, long major)
{
  gss_buffer_desc status_string;
  OM_uint32 message_context = 0;
  OM_uint32 maj = 0, min;
  size_t i;
  int rc = 0;

  if (!quiet)
    {
      printf (_("GSS-API major status code %ld (0x%lx).\n\n"), major, major);

      printf (_("   MSB                               "
		"                                  LSB\n"
		"   +-----------------+---------------"
		"--+---------------------------------+\n"
		"   |  Calling Error  |  Routine Error"
		"  |       Supplementary Info        |\n   | "));
      for (i = 0; i < 8; i++)
	printf ("%ld ", (major >> (31 - i)) & 1);
      printf ("| ");
      for (i = 0; i < 8; i++)
	printf ("%ld ", (major >> (23 - i)) & 1);
      printf ("| ");
      for (i = 0; i < 16; i++)
	printf ("%ld ", (major >> (15 - i)) & 1);
      printf (_("|\n"
		"   +-----------------+---------------"
		"--+---------------------------------+\n"
		"Bit 31            24  23            1"
		"6  15                             0\n\n"));
    }

  if (GSS_ROUTINE_ERROR (major))
    {
      if (!quiet)
	printf (_("Masked routine error %ld (0x%lx) shifted "
		  "into %ld (0x%lx):\n"),
		GSS_ROUTINE_ERROR (major),
		GSS_ROUTINE_ERROR (major),
		GSS_ROUTINE_ERROR (major) >>
		GSS_C_ROUTINE_ERROR_OFFSET,
		GSS_ROUTINE_ERROR (major) >> GSS_C_ROUTINE_ERROR_OFFSET);

      message_context = 0;
      do
	{
	  maj = gss_display_status (&min, GSS_ROUTINE_ERROR (major),
				    GSS_C_GSS_CODE, GSS_C_NO_OID,
				    &message_context, &status_string);
	  if (GSS_ERROR (maj))
	    {
	      error (0, 0, _("displaying status code failed (%d)"), maj);
	      rc = 1;
	      break;
	    }

	  printf ("%.*s\n", (int) status_string.length,
		  (char *) status_string.value);

	  gss_release_buffer (&min, &status_string);
	}
      while (message_context);

      if (!quiet)
	printf ("\n");
    }

  if (GSS_CALLING_ERROR (major))
    {
      if (!quiet)
	printf
	  (_("Masked calling error %ld (0x%lx) shifted into %ld (0x%lx):\n"),
	   GSS_CALLING_ERROR (major),
	   GSS_CALLING_ERROR (major),
	   GSS_CALLING_ERROR (major) >> GSS_C_CALLING_ERROR_OFFSET,
	   GSS_CALLING_ERROR (major) >> GSS_C_CALLING_ERROR_OFFSET);

      message_context = 0;
      do
	{
	  maj = gss_display_status (&min, GSS_CALLING_ERROR (major),
				    GSS_C_GSS_CODE, GSS_C_NO_OID,
				    &message_context, &status_string);
	  if (GSS_ERROR (maj))
	    {
	      error (0, 0, _("displaying status code failed (%d)"), maj);
	      rc = 1;
	      break;
	    }

	  printf ("%.*s\n", (int) status_string.length,
		  (char *) status_string.value);

	  gss_release_buffer (&min, &status_string);
	}
      while (message_context);

      if (!quiet)
	printf ("\n");
    }

  if (GSS_SUPPLEMENTARY_INFO (major))
    {
      if (!quiet)
	printf (_("Masked supplementary info %ld (0x%lx) shifted "
		  "into %ld (0x%lx):\n"),
		GSS_SUPPLEMENTARY_INFO (major),
		GSS_SUPPLEMENTARY_INFO (major),
		GSS_SUPPLEMENTARY_INFO (major) >>
		GSS_C_SUPPLEMENTARY_OFFSET,
		GSS_SUPPLEMENTARY_INFO (major) >> GSS_C_SUPPLEMENTARY_OFFSET);

      message_context = 0;
      do
	{
	  maj = gss_display_status (&min,
				    GSS_SUPPLEMENTARY_INFO (major),
				    GSS_C_GSS_CODE, GSS_C_NO_OID,
				    &message_context, &status_string);
	  if (GSS_ERROR (maj))
	    {
	      error (0, 0, _("displaying status code failed (%d)"), maj);
	      rc = 1;
	      break;
	    }

	  printf ("%.*s\n", (int) status_string.length,
		  (char *) status_string.value);

	  gss_release_buffer (&min, &status_string);
	}
      while (message_context);

      if (!quiet)
	printf ("\n");
    }

  if (major == GSS_S_COMPLETE)
    printf (_("No error\n"));

  return rc;
}

static int
list_mechanisms (unsigned quiet)
{
  OM_uint32 maj, min;
  gss_OID_set mech_set;
  size_t i;
  gss_buffer_desc sasl_mech_name;
  gss_buffer_desc mech_name;
  gss_buffer_desc mech_description;

  maj = gss_indicate_mechs (&min, &mech_set);
  if (GSS_ERROR (maj))
    {
      error (0, 0, _("indicating mechanisms failed (%d)"), maj);
      return 1;
    }

  printf ("Found %lu supported mechanisms.\n",
	  (unsigned long) mech_set->count);

  for (i = 0; i < mech_set->count; i++)
    {
      printf ("\nMechanism %lu:\n", (unsigned long) i);

      maj = gss_inquire_saslname_for_mech (&min, mech_set->elements++,
					   &sasl_mech_name, &mech_name,
					   &mech_description);
      if (GSS_ERROR (maj))
	{
	  error (0, 0, _("inquiring information about mechanism failed (%d)"),
		 maj);
	  continue;
	}

      printf ("\tMechanism name: %.*s\n",
	      (int) mech_name.length, (char *) mech_name.value);
      printf ("\tMechanism description: %.*s\n",
	      (int) mech_description.length, (char *) mech_description.value);
      printf ("\tSASL Mechanism name: %.*s\n",
	      (int) sasl_mech_name.length, (char *) sasl_mech_name.value);
    }

  return 0;
}

static ssize_t
gettrimline (char **line, size_t * n, FILE * fh)
{
  ssize_t s = getline (line, n, fh);

  if (s >= 2)
    {
      if ((*line)[strlen (*line) - 1] == '\n')
	(*line)[strlen (*line) - 1] = '\0';
      if ((*line)[strlen (*line) - 1] == '\r')
	(*line)[strlen (*line) - 1] = '\0';
    }

  return s;
}

static int
init_sec_context (unsigned quiet, const char *mech, const char *server)
{
  OM_uint32 maj, min;
  gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
  gss_name_t servername = GSS_C_NO_NAME;
  gss_buffer_desc inbuf_desc;
  gss_buffer_t inbuf = GSS_C_NO_BUFFER;
  gss_buffer_desc bufdesc;
  gss_buffer_desc sasl_mech_name;
  gss_OID mech_type;
  size_t outlen;
  char *out;
  ssize_t s;
  char *line = NULL;
  size_t n = 0;
  bool ok;
  OM_uint32 ret_flags;

  sasl_mech_name.length = strlen (mech);
  sasl_mech_name.value = (void *) mech;

  maj = gss_inquire_mech_for_saslname (&min, &sasl_mech_name, &mech_type);
  if (GSS_ERROR (maj))
    error (EXIT_FAILURE, 0,
	   _("inquiring mechanism for SASL name (%d/%d)"), maj, min);

  if (server)
    {
      gss_buffer_desc namebuf;

      namebuf.length = strlen (server);
      namebuf.value = (void *) server;

      maj = gss_import_name (&min, &namebuf, GSS_C_NT_HOSTBASED_SERVICE,
			     &servername);
      if (GSS_ERROR (maj))
	error (EXIT_FAILURE, 0,
	       _("could not import server name \"%s\" (%d/%d)"),
	       server, maj, min);
    }

  do
    {
      maj = gss_init_sec_context (&min,
				  GSS_C_NO_CREDENTIAL,
				  &ctx,
				  servername,
				  mech_type,
				  GSS_C_MUTUAL_FLAG |
				  GSS_C_REPLAY_FLAG |
				  GSS_C_SEQUENCE_FLAG,
				  0,
				  GSS_C_NO_CHANNEL_BINDINGS,
				  inbuf, NULL, &bufdesc, &ret_flags, NULL);
      if (GSS_ERROR (maj))
	error (EXIT_FAILURE, 0,
	       _("initializing security context failed (%d/%d)"), maj, min);

      outlen = base64_encode_alloc (bufdesc.value, bufdesc.length, &out);
      if (out == NULL && outlen == 0 && bufdesc.length != 0)
	error (EXIT_FAILURE, 0, _("base64 input too long"));
      if (out == NULL)
	error (EXIT_FAILURE, errno, _("malloc"));

      if (!quiet)
	{
	  if (maj == GSS_S_COMPLETE && bufdesc.length == 0)
	    printf ("Context has been initialized.\n");
	  else if (maj == GSS_S_COMPLETE)
	    printf ("Context has been initialized.  Final context token:\n");
	  else if (maj == GSS_S_CONTINUE_NEEDED &&
		   (ret_flags & GSS_C_PROT_READY_FLAG))
	    printf ("Context token (protection is available):\n");
	  else if (maj == GSS_S_CONTINUE_NEEDED)
	    printf ("Context token:\n");
	}
      if (bufdesc.length != 0)
	printf ("%s\n", out);

      free (out);

      if (maj == GSS_S_COMPLETE)
	break;

      if (!quiet)
	printf ("Input context token:\n");

      s = gettrimline (&line, &n, stdin);
      if (s == -1 && !feof (stdin))
	error (EXIT_FAILURE, errno, _("getline"));
      if (s == -1)
	error (EXIT_FAILURE, 0, _("EOF"));

      ok = base64_decode_alloc (line, strlen (line), &out, &outlen);
      if (!ok)
	error (EXIT_FAILURE, 0, _("base64 fail"));
      if (out == NULL)
	error (EXIT_FAILURE, errno, _("malloc"));

      inbuf_desc.value = out;
      inbuf_desc.length = outlen;
      inbuf = &inbuf_desc;
    }
  while (maj == GSS_S_CONTINUE_NEEDED);

  return 0;
}

static int
accept_sec_context (unsigned quiet, const char *mech, const char *server)
{
  OM_uint32 maj, min;
  gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
  gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
  gss_name_t client = GSS_C_NO_NAME;
  gss_buffer_desc bufdesc, bufdesc2;
  gss_OID mech_type = GSS_C_NO_OID;
  char *out;
  size_t outlen;
  ssize_t s;
  char *line = NULL;
  size_t n = 0;
  bool ok;
  OM_uint32 ret_flags;

  /*
    We support these variants:

    1) No call to gss_acquire_cred at all.  This happens if mech=NULL
    and server=NULL.

    2) Call to gss_acquire_cred with desired_mechs=GSS_C_NULL_OID_SET
    and desired_name=GSS_C_NO_NAME.  This happens if mech="*" (the
    string) and server=NULL.

    3) Call to gss_acquire_cred with desired_mechs=GSS_C_NULL_OID_SET
    and desired_name=server.  This happens if mech=NULL or mech="*"
    (the string) and server!=NULL.

    4) Call to gss_acquire_cred with desired_mechs=mech and
    desired_name=GSS_C_NO_NAME.  This happens if mech is a valid
    SASL-name and server=NULL.

    5) Call to gss_acquire_cred with desired_mechs=mech and
    desired_name=server.  This happens if mech is a valid SASL-name
    and server!=NULL.
   */

  if (mech || server)
    {
      gss_name_t servername = GSS_C_NO_NAME;
      gss_OID_set mech_types = GSS_C_NULL_OID_SET;

      if (mech && strcmp (mech, "*") != 0)
	{
	  gss_buffer_desc sasl_mech_name;

	  sasl_mech_name.length = strlen (mech);
	  sasl_mech_name.value = (void *) mech;

	  printf ("Inquiring mechanism OID for SASL name \"%s\"...\n", mech);
	  maj = gss_inquire_mech_for_saslname (&min, &sasl_mech_name,
					       &mech_type);
	  if (GSS_ERROR (maj))
	    error (EXIT_FAILURE, 0,
		   _("inquiring mechanism for SASL name (%d/%d)"), maj, min);
	}

      if (server)
	{
	  gss_buffer_desc namebuf;

	  namebuf.length = strlen (server);
	  namebuf.value = (void *) server;

	  printf ("Importing name \"%s\"...\n", server);
	  maj = gss_import_name (&min, &namebuf, GSS_C_NT_HOSTBASED_SERVICE,
				 &servername);
	  if (GSS_ERROR (maj))
	    error (EXIT_FAILURE, 0,
		   _("could not import server name \"%s\" (%d/%d)"),
		   server, maj, min);
	}

      if (mech_type != GSS_C_NO_OID)
	{
	  maj = gss_create_empty_oid_set (&min, &mech_types);
	  if (GSS_ERROR (maj))
	    error (EXIT_FAILURE, 0, "gss_create_empty_oid_set (%d/%d)",
		   maj, min);

	  maj = gss_add_oid_set_member (&min, mech_type, &mech_types);
	  if (GSS_ERROR (maj))
	    error (EXIT_FAILURE, 0, "gss_add_oid_set_member (%d/%d)",
		   maj, min);
	}

      printf ("Acquiring credentials...\n");
      maj = gss_acquire_cred (&min, servername, 0, mech_types, GSS_C_ACCEPT,
			      &cred, NULL, NULL);
      if (GSS_ERROR (maj))
	error (EXIT_FAILURE, 0,
	       _("could not acquire server credentials (%d/%d)"), maj, min);

      if (mech_type != GSS_C_NO_OID)
	{
	  maj = gss_release_oid_set (&min, &mech_types);
	  if (GSS_ERROR (maj))
	    error (EXIT_FAILURE, 0, "gss_release_oid_set (%d/%d)", maj, min);
	}
    }

  do
    {
      if (!quiet)
	printf ("Input context token:\n");

      s = gettrimline (&line, &n, stdin);
      if (s == -1 && !feof (stdin))
	error (EXIT_FAILURE, errno, _("getline"));
      if (s == -1)
	error (EXIT_FAILURE, 0, _("EOF"));

      ok = base64_decode_alloc (line, strlen (line), &out, &outlen);
      if (!ok)
	error (EXIT_FAILURE, 0, _("base64 fail"));
      if (out == NULL)
	error (EXIT_FAILURE, errno, _("malloc"));

      bufdesc.value = out;
      bufdesc.length = outlen;

      maj = gss_accept_sec_context (&min,
				    &ctx,
				    cred,
				    &bufdesc,
				    GSS_C_NO_CHANNEL_BINDINGS,
				    &client,
				    &mech_type,
				    &bufdesc2, &ret_flags, NULL, NULL);
      if (GSS_ERROR (maj))
	error (EXIT_FAILURE, 0,
	       _("accepting security context failed (%d/%d)"), maj, min);

      outlen = base64_encode_alloc (bufdesc2.value, bufdesc2.length, &out);
      if (out == NULL && outlen == 0 && bufdesc2.length != 0)
	error (EXIT_FAILURE, 0, _("base64 input too long"));
      if (out == NULL)
	error (EXIT_FAILURE, errno, _("malloc"));

      if (!quiet)
	{
	  if (maj == GSS_S_COMPLETE && bufdesc2.length == 0)
	    printf ("Context has been accepted.\n");
	  else if (maj == GSS_S_COMPLETE)
	    printf ("Context has been accepted.  Final context token:\n");
	  else if (maj == GSS_S_CONTINUE_NEEDED &&
		   (ret_flags & GSS_C_PROT_READY_FLAG))
	    printf ("Context token (protection is available):\n");
	  else if (maj == GSS_S_CONTINUE_NEEDED)
	    printf ("Context token:\n");
	}
      if (bufdesc2.length != 0)
	printf ("%s\n", out);

      free (out);
    }
  while (maj == GSS_S_CONTINUE_NEEDED);

  return 0;
}

int
main (int argc, char *argv[])
{
  struct gengetopt_args_info args;
  int rc = 0;

  setlocale (LC_ALL, "");
  set_program_name (argv[0]);
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  if (cmdline_parser (argc, argv, &args) != 0)
    return 1;

  if (args.version_given)
    {
      version_etc (stdout, "gss", PACKAGE_NAME, VERSION,
		   "Simon Josefsson", (char *) NULL);
      return EXIT_SUCCESS;
    }

  if (args.help_given)
    usage (EXIT_SUCCESS);
  else if (args.major_given)
    rc = describe_major (args.quiet_given, args.major_arg);
  else if (args.list_mechanisms_given)
    rc = list_mechanisms (args.quiet_given);
  else if (args.init_sec_context_given)
    rc = init_sec_context (args.quiet_given, args.init_sec_context_arg,
			   args.server_name_arg);
  else if (args.accept_sec_context_given)
    rc = accept_sec_context (args.quiet_given, args.accept_sec_context_arg,
			     args.server_name_arg);
  else
    usage (EXIT_SUCCESS);

  return rc;
}
