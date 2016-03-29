#pragma once

#include <lf-queue/lf_queue.h>

typedef struct pf_writer {
	void *handle;
} pf_writer_t;

int pf_writer_start(pf_writer_t *writer, lf_queue *queue,
                    const char *file_name_prefix, int pid);
int pf_writer_stop(pf_writer_t *writer);
