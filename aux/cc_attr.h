#ifndef CC_ATTR_H
#define CC_ATTR_H

// wrapper: __has_attribute
#ifndef __has_attribute
#define __has_attribute(attr) 0
#endif

// attribute: noreturn
#if __has_attribute(__noreturn__)
#define NORETURN __attribute__((__noreturn__))
#else
#define NORETURN
#endif

// attribute: __unused__
#if __has_attribute(__unused__)
#define UNUSED __attribute__((__unused__))
#else
#define UNUSED
#endif

#if   defined(__GNUC__)
#define SUPPRESS_UNUSED_RESULT_WARN(something) do {     \
  _Pragma("GCC diagnostic push")                        \
  _Pragma("GCC diagnostic ignored \"-Wunused-result\"") \
  (something);                                          \
  _Pragma("GCC diagnostic pop")                         \
} while (0)
#elif defined(__clang__)
#define SUPPRESS_UNUSED_RESULT_WARN(something) do {       \
  _Pragma("clang diagnostic push")                        \
  _Pragma("clang diagnostic ignored \"-Wunused-result\"") \
  (something);                                            \
  _Pragma("clang diagnostic pop")                         \
#else
#define SUPPRESS_UNUSED_RESULT_WARN
#endif

#endif
