#ifndef __attribute__
/* This feature is available in gcc versions 2.5 and later.  */
# if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5)
#  define __attribute__(Spec)	/* empty */
# endif
#endif

static void fail (const char *format, ...)
  __attribute__ ((format (printf, 1, 2)));
static void success (const char *format, ...)
  __attribute__ ((format (printf, 1, 2)));

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
    exit (EXIT_FAILURE);
}

static void
success (const char *format, ...)
{
  va_list arg_ptr;

  va_start (arg_ptr, format);
  if (debug)
    vfprintf (stdout, format, arg_ptr);
  va_end (arg_ptr);
}
