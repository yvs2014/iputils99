#ifndef NI_AUX_H
#define NI_AUX_H

#include <stdint.h>

#ifdef NONCE_MEMORY
void iputils_srand(void);
#endif

int ntohsp(const uint16_t *p);

#endif
