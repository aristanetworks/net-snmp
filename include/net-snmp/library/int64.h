#ifndef INT64_INCLUDED
#define INT64_INCLUDED

#ifdef __cplusplus
extern          "C" {
#endif

    typedef struct counter64 NSU64;

#define I64CHARSZ 21

    void            divBy10(NSU64, NSU64 *, unsigned int *);
    void            multBy10(NSU64, NSU64 *);
    void            incrByU16(NSU64 *, unsigned int);
    void            incrByU32(NSU64 *, unsigned int);
    NETSNMP_IMPORT
    void            zeroNSU64(NSU64 *);
    int             isZeroNSU64(const NSU64 *);
    NETSNMP_IMPORT
    void            printNSU64(char *, const NSU64 *);
    NETSNMP_IMPORT
    void            printI64(char *, const NSU64 *);
    int             read64(NSU64 *, const char *);
    NETSNMP_IMPORT
    void            u64Subtract(const NSU64 * pu64one, const NSU64 * pu64two,
                                NSU64 * pu64out);
    void            u64Incr(NSU64 * pu64out, const NSU64 * pu64one);
    void            u64UpdateCounter(NSU64 * pu64out, const NSU64 * pu64one,
                                     const NSU64 * pu64two);
    void            u64Copy(NSU64 * pu64one, const NSU64 * pu64two);

    int             netsnmp_c64_check_for_32bit_wrap(NSU64 *old_val, NSU64 *new_val,
                                                     int adjust);
    NETSNMP_IMPORT
    int             netsnmp_c64_check32_and_update(struct counter64 *prev_val,
                                                   struct counter64 *new_val,
                                                   struct counter64 *old_prev_val,
                                                   int *need_wrap_check);

#ifdef __cplusplus
}
#endif
#endif
