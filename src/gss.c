/* gss.c --- Command line tool for GSS.
 * Copyright (C) 2004-2011 Simon Josefsson
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

/* For gettext. */
#include <locale.h>
#include <gettext.h>
#define _(String) gettext (String)

/* Get GSS header. */
#include <gss.h>

/* Command line parameter parser via gengetopt. */
#include "gss_cmd.h"

/* Gnulib utils. */
#include "progname.h"
#include "error.h"
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
      printf (_("GSS-API major status code %ld (0x%lx).\n\n"),
	      major, major);

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
		GSS_ROUTINE_ERROR (major) >>
		GSS_C_ROUTINE_ERROR_OFFSET);

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
		GSS_SUPPLEMENTARY_INFO (major) >>
		GSS_C_SUPPLEMENTARY_OFFSET);

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

  printf ("Found %lu supported mechanisms.\n", (unsigned long) mech_set->count);

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
  else
    usage (EXIT_SUCCESS);

  return rc;
}
