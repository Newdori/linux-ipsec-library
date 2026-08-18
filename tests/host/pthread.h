#ifndef IPSEC_TEST_PTHREAD_H
#define IPSEC_TEST_PTHREAD_H

/*
 * Parser-only Windows host tests include the internal context definition but
 * never create or operate on its mutex.  This opaque stand-in keeps those
 * tests independent from a Windows pthread compatibility package.  Product
 * builds always use the platform pthread.h on Linux.
 */
typedef struct IpsecTestPthreadMutex {
    void *pvOpaque;
} pthread_mutex_t;

#endif
