#ifndef NI_AUX_H
#define NI_AUX_H

#include <stdint.h>

#define NI_ARRAY_SIZE(arr) \
  (sizeof(arr) / sizeof((arr)[0]) + \
   sizeof(__typeof__(int[1 - 2 * \
	  !!__builtin_types_compatible_p(__typeof__(arr), \
					 __typeof__(&arr[0]))])) * 0)
#ifdef NONCE_MEMORY
void iputils_srand(void);
#endif

int ntohsp(const uint16_t *p);

#endif
