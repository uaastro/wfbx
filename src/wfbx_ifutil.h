#ifndef WFBX_IFUTIL_H
#define WFBX_IFUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Return center frequency in MHz for the provided interface name.
 * Returns 0 when the frequency cannot be determined or when the
 * platform lacks the required APIs.
 */
int wfbx_if_get_frequency_mhz(const char* ifname);

#ifdef __cplusplus
}
#endif

#endif /* WFBX_IFUTIL_H */
