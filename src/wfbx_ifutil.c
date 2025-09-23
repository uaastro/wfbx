#include "wfbx_ifutil.h"

#include <string.h>

#ifdef __linux__
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <math.h>
#include <stdint.h>

#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <linux/wireless.h>
#include <sys/ioctl.h>

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif
#ifndef NLA_OK
#define NLA_OK(nla, len) ((len) >= (int)sizeof(struct nlattr) && \
                          (nla)->nla_len >= sizeof(struct nlattr) && \
                          (nla)->nla_len <= (len))
#endif
#ifndef NLA_NEXT
#define NLA_NEXT(nla, len) ((len) -= NLA_ALIGN((nla)->nla_len), \
                            (struct nlattr*)(((char*)(nla)) + NLA_ALIGN((nla)->nla_len)))
#endif

#ifndef NLA_DATA
#define NLA_DATA(nla) ((void*)((char*)(nla) + NLA_HDRLEN))
#endif

/* Local netlink state */
static int g_nl_sock = -1;
static int g_nl_family_id = 0;
static uint32_t g_nl_seq = 0;

static uint16_t nla_get_u16(const struct nlattr* nla)
{
    uint16_t val;
    memcpy(&val, NLA_DATA(nla), sizeof(val));
    return val;
}

static uint32_t nla_get_u32(const struct nlattr* nla)
{
    uint32_t val;
    memcpy(&val, NLA_DATA(nla), sizeof(val));
    return val;
}

static int channel_to_freq_mhz(int channel)
{
    if (channel <= 0) return 0;
    if (channel == 14) return 2484;
    if (channel < 14) return 2407 + channel * 5;
    if (channel >= 182 && channel <= 196) return 4000 + channel * 5;
    return 5000 + channel * 5;
}

static int iwfreq_to_mhz(const struct iw_freq* wf)
{
    if (!wf) return 0;
    if (wf->m != 0) {
        double value = (double)wf->m;
        if (wf->e > 0) {
            for (int i = 0; i < wf->e; ++i) value *= 10.0;
        } else if (wf->e < 0) {
            for (int i = 0; i < -wf->e; ++i) value /= 10.0;
        }
        if (value > 0.0) {
            double mhz = value / 1e6;
            if (mhz >= 100.0) return (int)(mhz + 0.5);
            int ch_guess = (int)(value + 0.5);
            int freq_from_ch = channel_to_freq_mhz(ch_guess);
            if (freq_from_ch > 0) return freq_from_ch;
        }
    }
    if (wf->i > 0) {
        int freq_from_idx = channel_to_freq_mhz((int)wf->i);
        if (freq_from_idx > 0) return freq_from_idx;
    }
    if (wf->e == 0 && wf->m > 0) {
        int freq_from_channel = channel_to_freq_mhz((int)wf->m);
        if (freq_from_channel > 0) return freq_from_channel;
    }
    return 0;
}

static int ioctl_get_frequency_mhz(const char* ifname)
{
#ifdef SIOCGIWFREQ
    if (!ifname || !*ifname) return 0;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct iwreq req;
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, ifname, IFNAMSIZ);
    req.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(fd, SIOCGIWFREQ, &req) != 0) {
        close(fd);
        return 0;
    }
    struct iw_freq freq = req.u.freq;
    close(fd);
    return iwfreq_to_mhz(&freq);
#else
    (void)ifname;
    return 0;
#endif
}

static int nl80211_open_socket(void)
{
    if (g_nl_sock >= 0) return 0;
    g_nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if (g_nl_sock < 0) return -1;
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    if (bind(g_nl_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(g_nl_sock);
        g_nl_sock = -1;
        return -1;
    }
    return 0;
}

static int nl80211_resolve_family(void)
{
    if (g_nl_family_id > 0) return g_nl_family_id;
    if (nl80211_open_socket() != 0) return -1;

    char buf[4096];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
    struct genlmsghdr* genlh = (struct genlmsghdr*)(buf + NLMSG_HDRLEN);
    struct nlattr* na;

    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = GENL_ID_CTRL;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = ++g_nl_seq;
    nlh->nlmsg_pid = 0;

    genlh->cmd = CTRL_CMD_GETFAMILY;
    genlh->version = 1;

    na = (struct nlattr*)((char*)genlh + GENL_HDRLEN);
    na->nla_type = CTRL_ATTR_FAMILY_NAME;
    const char family_name[] = "nl80211";
    size_t name_len = sizeof(family_name);
    na->nla_len = NLA_HDRLEN + name_len;
    memcpy((char*)NLA_DATA(na), family_name, name_len);
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN + na->nla_len);

    struct sockaddr_nl dst;
    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;
    if (sendto(g_nl_sock, nlh, nlh->nlmsg_len, 0, (struct sockaddr*)&dst, sizeof(dst)) < 0)
        return -1;

    int len = recv(g_nl_sock, buf, sizeof(buf), 0);
    if (len < 0) return -1;

    for (struct nlmsghdr* hdr = (struct nlmsghdr*)buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {
        if (hdr->nlmsg_type == NLMSG_ERROR) return -1;
        struct genlmsghdr* gh = (struct genlmsghdr*)NLMSG_DATA(hdr);
        int attrlen = hdr->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
        struct nlattr* attr = (struct nlattr*)((char*)gh + GENL_HDRLEN);
        for (; NLA_OK(attr, attrlen); attr = NLA_NEXT(attr, attrlen)) {
            if (attr->nla_type == CTRL_ATTR_FAMILY_ID) {
                g_nl_family_id = nla_get_u16(attr);
                return g_nl_family_id;
            }
        }
    }
    return -1;
}

static int nl80211_get_frequency(const char* ifname)
{
    if (!ifname) return 0;
    if (nl80211_resolve_family() <= 0) return 0;
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) return 0;

    char buf[4096];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr* nlh = (struct nlmsghdr*)buf;
    struct genlmsghdr* genlh = (struct genlmsghdr*)(buf + NLMSG_HDRLEN);
    struct nlattr* na;

    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    nlh->nlmsg_type = g_nl_family_id;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++g_nl_seq;
    nlh->nlmsg_pid = 0;

    genlh->cmd = NL80211_CMD_GET_INTERFACE;
    genlh->version = 0;

    na = (struct nlattr*)((char*)genlh + GENL_HDRLEN);
    na->nla_type = NL80211_ATTR_IFINDEX;
    na->nla_len = NLA_HDRLEN + sizeof(uint32_t);
    memcpy(NLA_DATA(na), &ifindex, sizeof(uint32_t));
    nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN + na->nla_len);

    struct sockaddr_nl dst;
    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;
    if (sendto(g_nl_sock, nlh, nlh->nlmsg_len, 0, (struct sockaddr*)&dst, sizeof(dst)) < 0)
        return 0;

    int len = recv(g_nl_sock, buf, sizeof(buf), 0);
    if (len < 0) return 0;

    int freq_mhz = 0;
    int wiphy_id = -1;
    for (struct nlmsghdr* hdr = (struct nlmsghdr*)buf; NLMSG_OK(hdr, len); hdr = NLMSG_NEXT(hdr, len)) {
        if (hdr->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr* err = (struct nlmsgerr*)NLMSG_DATA(hdr);
            if (err->error == 0) continue;
            return 0;
        }
        if (hdr->nlmsg_type != g_nl_family_id) continue;
        struct genlmsghdr* gh = (struct genlmsghdr*)NLMSG_DATA(hdr);
        int attrlen = hdr->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
        struct nlattr* attr = (struct nlattr*)((char*)gh + GENL_HDRLEN);
        for (; NLA_OK(attr, attrlen); attr = NLA_NEXT(attr, attrlen)) {
            if (attr->nla_type == NL80211_ATTR_WIPHY_FREQ) {
                freq_mhz = (int)nla_get_u32(attr);
            }
            if (attr->nla_type == NL80211_ATTR_WIPHY) {
                wiphy_id = (int)nla_get_u32(attr);
            }
        }
    }
    if (freq_mhz > 0) return freq_mhz;
#ifdef NL80211_CMD_GET_WIPHY
    if (wiphy_id >= 0) {
        memset(buf, 0, sizeof(buf));
        struct nlmsghdr* nlh2 = (struct nlmsghdr*)buf;
        struct genlmsghdr* genlh2 = (struct genlmsghdr*)(buf + NLMSG_HDRLEN);
        struct nlattr* na2;

        nlh2->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
        nlh2->nlmsg_type = g_nl_family_id;
        nlh2->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        nlh2->nlmsg_seq = ++g_nl_seq;
        nlh2->nlmsg_pid = 0;

        genlh2->cmd = NL80211_CMD_GET_WIPHY;
        genlh2->version = 0;

        na2 = (struct nlattr*)((char*)genlh2 + GENL_HDRLEN);
        na2->nla_type = NL80211_ATTR_WIPHY;
        na2->nla_len = NLA_HDRLEN + sizeof(uint32_t);
        memcpy(NLA_DATA(na2), &wiphy_id, sizeof(uint32_t));
        nlh2->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN + na2->nla_len);

        struct sockaddr_nl dst2;
        memset(&dst2, 0, sizeof(dst2));
        dst2.nl_family = AF_NETLINK;
        if (sendto(g_nl_sock, nlh2, nlh2->nlmsg_len, 0, (struct sockaddr*)&dst2, sizeof(dst2)) >= 0) {
            int len2 = recv(g_nl_sock, buf, sizeof(buf), 0);
            if (len2 >= 0) {
                for (struct nlmsghdr* hdr2 = (struct nlmsghdr*)buf; NLMSG_OK(hdr2, len2); hdr2 = NLMSG_NEXT(hdr2, len2)) {
                    if (hdr2->nlmsg_type == NLMSG_ERROR) {
                        struct nlmsgerr* err2 = (struct nlmsgerr*)NLMSG_DATA(hdr2);
                        if (err2->error == 0) continue;
                        break;
                    }
                    if (hdr2->nlmsg_type != g_nl_family_id) continue;
                    struct genlmsghdr* gh2 = (struct genlmsghdr*)NLMSG_DATA(hdr2);
                    int attrlen2 = hdr2->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
                    struct nlattr* attr2 = (struct nlattr*)((char*)gh2 + GENL_HDRLEN);
                    for (; NLA_OK(attr2, attrlen2); attr2 = NLA_NEXT(attr2, attrlen2)) {
                        if (attr2->nla_type == NL80211_ATTR_WIPHY_FREQ) {
                            freq_mhz = (int)nla_get_u32(attr2);
                            break;
                        }
                    }
                    if (freq_mhz > 0) break;
                }
            }
        }
    }
#else
    (void)wiphy_id;
#endif
    return freq_mhz;
}

int wfbx_if_get_frequency_mhz(const char* ifname)
{
    int freq_mhz = ioctl_get_frequency_mhz(ifname);
    if (freq_mhz > 0) return freq_mhz;
    return nl80211_get_frequency(ifname);
}

#else /* !__linux__ */

int wfbx_if_get_frequency_mhz(const char* ifname)
{
    (void)ifname;
    return 0;
}

#endif /* __linux__ */
