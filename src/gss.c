/* gss.c	Command line interface to GSS
 * Copyright (C) 2003  Simon Josefsson
 *
 * This file is part of GPL GSS-API.
 *
 * GPL GSS-API is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GPL GSS-API is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GPL GSS-API; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "internal.h"

const char *argp_program_version = "gss (" PACKAGE_STRING ")";
const char *argp_program_bug_address = PACKAGE_BUGREPORT;

int silent;
int verbose;

static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  switch (key)
    {
    case 'q':
      silent = 1;
      break;

    case 'v':
      verbose = 1;
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }

  return 0;
}

static struct argp_option options[] = {

  {0, 0, 0, 0, "Other options:", 1000},

  {"verbose", 'v', 0, 0, "Produce verbose output."},

  {"quiet", 'q', 0, 0, "Don't produce any diagnostic output."},

  {"silent", 0, 0, OPTION_ALIAS},

  {0}
};

static struct argp argp = {
  options,
  parse_opt,
  0,
  "GSS (gss) -- Command line interface to GSS."
};

int
main (int argc, char *argv[])
{
#ifdef HAVE_LOCALE_H
  setlocale (LC_ALL, "");
#endif
  bindtextdomain (PACKAGE, LOCALEDIR);

  argp_parse (&argp, argc, argv, 0, 0, NULL);

  puts("hi");

  return 0;
}
