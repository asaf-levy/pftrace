#ifndef __PF_WRITER_H_INCLUDED__
#define __PF_WRITER_H_INCLUDED__

#include <lf-queue/lf_queue.h>

int start_writer(lf_queue_handle_t queue, const char *file_name_prefix);
int stop_writer(void);

#endif