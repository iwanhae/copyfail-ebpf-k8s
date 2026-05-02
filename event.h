#ifndef __EVENT_H__
#define __EVENT_H__

struct event {
    unsigned int pid;
    unsigned int uid;
    unsigned int gid;
    char comm[16];
    int action;
};

#define EVENT_ACTION_BLOCKED 0
#define EVENT_ACTION_KILLED  1

#endif
