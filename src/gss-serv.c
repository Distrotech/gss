/* gss-serv.c --- GSS server.
 * Copyright (C) 2004-2012 Simon Josefsson
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
#include "gss_serv_cmd.h"

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
Generic Security Service test server.\n\
\n\
"), stdout);
      fputs (_("\
Mandatory arguments to long options are mandatory for short options too.\n\
"), stdout);
      fputs (_("\
  -h, --help        Print help and exit.\n\
  -V, --version     Print version and exit.\n\
"), stdout);
      fputs (_("\
  -q, --quiet       Silent operation (default=off).\n\
"), stdout);
      emit_bug_reporting_address ();
    }
  exit (status);
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
accept_sec_context (unsigned quiet)
{
  OM_uint32 maj, min;
  gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
  gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
  gss_name_t client = GSS_C_NO_NAME;
  gss_buffer_desc bufdesc, bufdesc2;
  gss_OID mech_type;
  char *out;
  size_t outlen;
  ssize_t s;
  char *line = NULL;
  size_t n = 0;
  bool ok;

  do
    {
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
				    &bufdesc2, NULL, NULL, NULL);
      if (GSS_ERROR (maj))
	error (EXIT_FAILURE, 0,
	       _("accepting security context failed (%d/%d)"), maj, min);

      outlen = base64_encode_alloc (bufdesc2.value, bufdesc2.length, &out);
      if (out == NULL && outlen == 0 && bufdesc2.length != 0)
	error (EXIT_FAILURE, 0, _("base64 input too long"));
      if (out == NULL)
	error (EXIT_FAILURE, errno, _("malloc"));

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

  accept_sec_context (args.quiet_given);

  return 0;
}
