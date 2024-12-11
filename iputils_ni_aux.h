#ifndef IPUTILS_NI_AUX_H
#define IPUTILS_NI_AUX_H

#define ARRAY_SIZE(arr) \
  (sizeof(arr) / sizeof((arr)[0]) + \
   sizeof(__typeof__(int[1 - 2 * \
	  !!__builtin_types_compatible_p(__typeof__(arr), \
					 __typeof__(&arr[0]))])) * 0)
#if PING6_NONCE_MEMORY
void iputils_srand(void);
#endif

#endif
