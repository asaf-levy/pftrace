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

typedef struct fmt_msg {
    uint16_t msg_id;
    uint16_t fmt_len;
} fmt_msg_t;

typedef struct trc_msg {
    uint16_t msg_id;
    uint16_t buf_len;
    uint32_t tid;
    uint64_t timestamp;
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