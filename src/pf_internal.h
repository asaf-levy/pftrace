#ifndef __PF_INTERNAL_H_INCLUDED__
#define __PF_INTERNAL_H_INCLUDED__

typedef struct fmt_msg {
    uint16_t msg_id;
    uint16_t fmt_len;
    char *fmt;
} fmt_msg_t;

typedef struct trc_msg {
    uint16_t msg_id;
    uint16_t buf_len;
    uint32_t tid;
    uint64_t timestamp;
    char *buff;
} trc_msg_t;

#define FMT_MSG_TYPE 1
#define TRC_MSG_TYPE 2
typedef struct queue_msg {
    int type;
    union {
	fmt_msg_t fmt_msg;
	trc_msg_t trc_msg;
    };
} queue_msg_t;

#endif