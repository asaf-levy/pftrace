#pragma once

#include <stdint.h>
#include "pf_trace.h"

#define PF_MAX_MSG_ID 65535

// TODO write this to the trace files
typedef struct version_msg {
    uint64_t magic;
    uint64_t version;
} version_msg_t;

#define MD_FILE_MAGIC   0x0123abcd
#define TRC_FILE_MAGIC  0x0123abce
#define NSEC_IN_SEC     1000000000
#define DEAMON_QUEUE_SIZE 8
#define DEAMON_SHM_NAME  "/pf_trc_daemon"

typedef struct __attribute__((packed)) fmt_msg {
    uint16_t msg_id;
    uint16_t fmt_len;
} fmt_msg_t;

typedef struct __attribute__((packed)) trc_msg {
    uint64_t timestamp_nsec;
    uint16_t msg_id;
    uint16_t buf_len;
    uint16_t tid;
} trc_msg_t;

#define FMT_MSG_TYPE 1
#define TRC_MSG_TYPE 2
typedef struct queue_msg {
    int type;
    union {
	fmt_msg_t fmt_msg;
	trc_msg_t trc_msg;
    };
    // followed by the message buffer
} queue_msg_t;


typedef struct daemon_setup_msg {
    int proc_pid;
    char file_name_prefix[PF_MAX_NAME];
    char shm_name[PF_MAX_NAME];
    pf_trace_config_t cfg;
} daemon_setup_msg_t;

typedef struct daemon_teardown_msg {
    int proc_pid;
} daemon_teardown_msg_t;

#define DSETUP_MSG_TYPE 1
#define DTEARDOWN_MSG_TYPE 2
typedef struct daemon_msg {
    int type;
    union {
        daemon_setup_msg_t setup_msg;
        daemon_teardown_msg_t teardown_msg;
    };
} daemon_msg_t;

static inline char *qmsg_buffer(queue_msg_t *queue_msg) {
	return (char*)queue_msg + sizeof(*queue_msg);
}