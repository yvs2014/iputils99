#ifndef PING_AUX_H
#define PING_AUX_H

char *str_family(int family);
char *str_socktype(int socktype);
double ping_strtod(const char *str, const char *err_msg);
int parse_flow(const char *str);
int parse_tos(const char *str);

#endif
