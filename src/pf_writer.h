#pragma once

#include <lf-queue/lf_queue.h>

typedef struct pf_writer pf_writer;

// Starts a trace writer thread that reads trace messages from the provided queue,
// and writes them to a binary trace file.
 pf_writer *pf_writer_start(lf_queue *queue, const char *file_name_prefix, int pid);
// Stops the provided trace writer thread
int pf_writer_stop(pf_writer *writer);
