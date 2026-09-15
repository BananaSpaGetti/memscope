/*
 * repl.h -- the interactive scanner loop, entered by the `scan` subcommand.
 *
 * This existed as a bare forward declaration in main_memscope.c, excused on the grounds that
 * the task which wired `scan` up was allowed to touch only two files and could not add a
 * header. It can now.
 */
#ifndef MEMSCOPE_REPL_H
#define MEMSCOPE_REPL_H

/* Attaches to `target` (a decimal pid or a process-name substring) and runs the REPL until
 * the user quits or stdin ends. Returns the process exit code. */
int repl_main(const char *target);

#endif /* MEMSCOPE_REPL_H */
