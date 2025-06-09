#ifndef STR2NUM_H
#define STR2NUM_H

double   str2dbl(const char *str,    double min,    double max, const char *msg);
long long str2ll(const char *str, long long min, long long max, const char *msg);

#define VALID_INTSTR(min, max) str2ll(optarg, (min), (max), NULL)

#endif
