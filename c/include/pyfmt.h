/*
 * pyfmt.h -- number formatting that matches Python's, so the C port's output can be diffed
 * against memscope.py byte for byte.
 *
 * These were written twice, once in main_memscope.c and once in repl.c, because each task that
 * needed them was allowed to edit only its own file. That is a planning artifact, not a design
 * reason: the float formatter is the most intricate code in the port, and two copies meant a
 * fix to one silently missed `memscope read --type float` or the REPL's `list`, with nothing
 * comparing them.
 */
#ifndef MEMSCOPE_PYFMT_H
#define MEMSCOPE_PYFMT_H

#include <stddef.h>

#include "values.h"

void ms_format_python_double(double value, char *out, size_t out_cap);
void ms_format_value(const MsValue *value, char *out, size_t out_cap);

#endif /* MEMSCOPE_PYFMT_H */
