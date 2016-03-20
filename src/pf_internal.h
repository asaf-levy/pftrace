#ifndef __PF_INTERNAL_H_INCLUDED__
#define __PF_INTERNAL_H_INCLUDED__

#include <stdint.h>

#define PF_MAX_MSG_ID 65535

// TODO write this to the trace files
typedef struct version_msg {
    uint64_t magic;
    uint64_t version;
} version_msg_t;

#define MD_FILE_MAGIC   0x0123abcd
#define TRC_FILE_MAGIC  0x0123abce
#define NSEC_IN_SEC     1000000000

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

static inline char *qmsg_buffer(queue_msg_t *queue_msg) {
	return (char*)queue_msg + sizeof(*queue_msg);
}

#endif