/* gss.c --- Command line tool for GSS.
 * Copyright (C) 2004  Simon Josefsson
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
#include <string.h>

/* For gettext. */
#ifdef HAVE_LOCALE_H
# include <locale.h>
#else
# define setlocale(Category, Locale)	/* empty */
#endif
#include <gettext.h>
#define _(String) gettext (String)

/* Get GSS header. */
#include <gss.h>

/* Command line parameter parser via gengetopt. */
#include "gss_cmd.h"

int
main (int argc, char *argv[])
{
  struct gengetopt_args_info args;
  gss_buffer_desc status_string;
  OM_uint32 message_context = 0;
  OM_uint32 maj = 0, min;
  int rc = 0;
  size_t i;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  if (cmdline_parser (argc, argv, &args) != 0)
    return 1;

  if (!args.major_given)
    {
      fprintf (stderr, _("%s: missing parameter\n"), argv[0]);
      fprintf (stderr, _("Try `%s --help' for more information.\n"), argv[0]);
      cmdline_parser_print_help ();
      return 1;
    }

  if (!args.quiet_given)
    {
      printf (_("GSS-API major status code %ld (0x%lx).\n\n"),
	      args.major_arg, args.major_arg);

      printf (_("   MSB                               "
		"                                  LSB\n"
		"   +-----------------+---------------"
		"--+---------------------------------+\n"
		"   |  Calling Error  |  Routine Error"
		"  |       Supplementary Info        |\n   | "));
      for (i = 0; i < 8; i++)
	printf ("%ld ", (args.major_arg >> (31 - i)) & 1);
      printf ("| ");
      for (i = 0; i < 8; i++)
	printf ("%ld ", (args.major_arg >> (23 - i)) & 1);
      printf ("| ");
      for (i = 0; i < 16; i++)
	printf ("%ld ", (args.major_arg >> (15 - i)) & 1);
      printf (_("|\n"
		"   +-----------------+---------------"
		"--+---------------------------------+\n"
		"Bit 31            24  23            1"
		"6  15                             0\n\n"));
    }

  if (GSS_ROUTINE_ERROR (args.major_arg))
    {
      if (!args.quiet_given)
	printf (_("Masked routine error %ld (0x%lx) shifted "
		  "into %ld (0x%lx):\n"),
		GSS_ROUTINE_ERROR (args.major_arg),
		GSS_ROUTINE_ERROR (args.major_arg),
		GSS_ROUTINE_ERROR (args.
				   major_arg) >> GSS_C_ROUTINE_ERROR_OFFSET,
		GSS_ROUTINE_ERROR (args.
				   major_arg) >> GSS_C_ROUTINE_ERROR_OFFSET);

      message_context = 0;
      do
	{
	  maj = gss_display_status (&min, GSS_ROUTINE_ERROR (args.major_arg),
				    GSS_C_GSS_CODE, GSS_C_NO_OID,
				    &message_context, &status_string);
	  if (GSS_ERROR (maj))
	    {
	      fprintf (stderr, _("%s: displaying status code failed\n"),
		       argv[0]);
	      rc = 1;
	      break;
	    }

	  printf ("%.*s\n", (int) status_string.length,
		  (char *) status_string.value);

	  gss_release_buffer (&min, &status_string);
	}
      while (message_context);

      if (!args.quiet_given)
	printf ("\n");
    }

  if (GSS_CALLING_ERROR (args.major_arg))
    {
      if (!args.quiet_given)
	printf
	  (_("Masked calling error %ld (0x%lx) shifted into %ld (0x%lx):\n"),
	   GSS_CALLING_ERROR (args.major_arg),
	   GSS_CALLING_ERROR (args.major_arg),
	   GSS_CALLING_ERROR (args.major_arg) >> GSS_C_CALLING_ERROR_OFFSET,
	   GSS_CALLING_ERROR (args.major_arg) >> GSS_C_CALLING_ERROR_OFFSET);

      message_context = 0;
      do
	{
	  maj = gss_display_status (&min, GSS_CALLING_ERROR (args.major_arg),
				    GSS_C_GSS_CODE, GSS_C_NO_OID,
				    &message_context, &status_string);
	  if (GSS_ERROR (maj))
	    {
	      fprintf (stderr, _("%s: displaying status code failed\n"),
		       argv[0]);
	      rc = 1;
	      break;
	    }

	  printf ("%.*s\n", (int) status_string.length,
		  (char *) status_string.value);

	  gss_release_buffer (&min, &status_string);
	}
      while (message_context);

      if (!args.quiet_given)
	printf ("\n");
    }

  if (GSS_SUPPLEMENTARY_INFO (args.major_arg))
    {
      if (!args.quiet_given)
	printf (_("Masked supplementary info %ld (0x%lx) shifted "
		  "into %ld (0x%lx):\n"),
		GSS_SUPPLEMENTARY_INFO (args.major_arg),
		GSS_SUPPLEMENTARY_INFO (args.major_arg),
		GSS_SUPPLEMENTARY_INFO (args.major_arg) >>
		GSS_C_SUPPLEMENTARY_OFFSET,
		GSS_SUPPLEMENTARY_INFO (args.major_arg) >>
		GSS_C_SUPPLEMENTARY_OFFSET);

      message_context = 0;
      do
	{
	  maj = gss_display_status (&min,
				    GSS_SUPPLEMENTARY_INFO (args.major_arg),
				    GSS_C_GSS_CODE, GSS_C_NO_OID,
				    &message_context, &status_string);
	  if (GSS_ERROR (maj))
	    {
	      fprintf (stderr, _("%s: displaying status code failed\n"),
		       argv[0]);
	      rc = 1;
	      break;
	    }

	  printf ("%.*s\n", (int) status_string.length,
		  (char *) status_string.value);

	  gss_release_buffer (&min, &status_string);
	}
      while (message_context);

      if (!args.quiet_given)
	printf ("\n");
    }

  if (args.major_arg == GSS_S_COMPLETE)
    printf (_("No error\n"));

  return rc;
}
