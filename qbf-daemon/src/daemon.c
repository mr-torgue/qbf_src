#include <linux/module.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <poll.h>
#include <math.h>
#include <dns_message.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <assert.h>
#include <map.h>
#include <constants.h>
#include <signal.h>

uint32_t MAXUDP = 1232;
uint32_t our_addr;
uint32_t is_resolver = false;
int MODE = 2;   // 0:Sequential 1:Parallel-2RTT 2:Parallel-1RTT
int ALG = 0;    // 0:Falcon-512 1:Dilithium 2:SPHINCS 3:P256_Falcon-512 4:P256-Dilithium2 5:MAYO1
bool BYPASS = false;
bool debug = true; // Set to true to print logs

void handle_signal(int sig) {
    exit(0); 
}

char *itoa(uint16_t in) {
    char *res = NULL;
    int num_bytes = snprintf(NULL, 0, "%hu", in) + 1;
    res = malloc(sizeof(char) * num_bytes);
    snprintf(res, num_bytes, "%hu", in);
    return res;
}

char *AppendStrings(const char *A, const char *B) {
    int lenA = strlen(A);
    int lenB = strlen(B);
    char *C = (char *) malloc(lenA + lenB + 1);
    memcpy(C, A, lenA);
    memcpy(C + lenA, B, lenB);
    C[lenA + lenB] = '\0';
    return C;
}

char *qname_2_qnamef(char *qname, int frag_num) {
    char *frag_num_str = malloc(sizeof(char) * (int) log10(frag_num));
    sprintf(frag_num_str, "%d", frag_num);

    return AppendStrings(AppendStrings("?", AppendStrings(frag_num_str, "?")), qname);
}

char *qnamef_2_qname(char *qnamef, int *frag_num) {
    int i = 1;
    for (; i < strlen(qnamef); i++) {
        if (qnamef[i] == '?')
            break;
    }
    i++;

    char *frag_str = malloc(i - 2 + 1);
    strncpy(frag_str, qnamef + 1, i - 2);
    frag_str[i - 2] = '\0';
    *frag_num = atoi(frag_str);

    char *qname = malloc(strlen(qnamef) - i);
    strncpy(qname, qnamef + i, strlen(qnamef) - i);
    return qname;
}

void print_ip_port(unsigned int src_ip, unsigned int dst_ip,
                   unsigned int src_port, unsigned int dst_port) {
    unsigned char bytes[4];
    bytes[0] = src_ip & 0xFF;
    bytes[1] = (src_ip >> 8) & 0xFF;
    bytes[2] = (src_ip >> 16) & 0xFF;
    bytes[3] = (src_ip >> 24) & 0xFF;
    printf("src_ip: %d.%d.%d.%d src_port: %d\n", bytes[0], bytes[1], bytes[2],
           bytes[3], src_port);
    bytes[0] = dst_ip & 0xFF;
    bytes[1] = (dst_ip >> 8) & 0xFF;
    bytes[2] = (dst_ip >> 16) & 0xFF;
    bytes[3] = (dst_ip >> 24) & 0xFF;
    printf("dst_ip: %d.%d.%d.%d dst_port: %d\n", bytes[0], bytes[1], bytes[2],
           bytes[3], dst_port);

}

void ERROR(void) {
    assert(false);
}

typedef struct RequesterMsgStore {
    DNSMessage *m_arr[25];
    int num_required_frags;
    int num_stored_frags;
} RequesterMsgStore;

typedef struct ResponderMsgStore {
    DNSMessage *m_arr[25];
    int num_required_frags;
} ResponderMsgStore;

typedef struct ToSendDNSMessage {
    DNSMessage *m_arr[25];
    int m_arr_size;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    bool is_tcp;
    bool swap_ip;
} ToSendDNSMessage;

bool update_max_udp(DNSMessage *msg, uint16_t new_size) {
    bool res = false;
    // First we need to find opt. It's always located in
    // the additional section.
    uint16_t arcount = msg->arcount;
    for (uint16_t i = 0; i < arcount; i++) {
        ResourceRecord *rr = msg->additional_section[i];
        if (rr->type == OPT) {
            rr->clas = new_size;    // the class field in opt is used for max UDP size
            res = true;
            break;
        }
    }

    return res;
}

bool construct_intermediate_message(DNSMessage *in, DNSMessage **out) {
    clone_dnsmessage(in, out);
    return update_max_udp(*out, 65507U);
}


// From The Practice of Programming
uint16_t hash_16bit(unsigned char *in, size_t in_len) {
    uint16_t h;
    unsigned char *p = in;

    h = 0;
    for (size_t i = 0; i < in_len; i++) {
        h = 37 * h + p[i];
    }

    return h;
}

typedef struct shared_map {
    sem_t lock;
    hashmap *map;
} shared_map;

shared_map responder_cache;
hashmap *requester_state;
hashmap *responder_state;
shared_map connection_info;

typedef struct conn_info {
    int fd;
    void *transport_header;
    bool is_tcp;
    struct iphdr *iphdr;
    int frag_num;
    char *qname;
} conn_info;

void init_shared_map(shared_map *map) {
    sem_init(&(map->lock), 0, 1);
    map->map = hashmap_create();
}

void create_generic_socket(uint32_t dest_addr, uint16_t dest_port, bool is_tcp,
                           int *out_fd) {
    struct sockaddr_in addrinfo;
    addrinfo.sin_family = AF_INET;
    addrinfo.sin_addr.s_addr = dest_addr;
    int sock_type = -1;
    if (is_tcp) {
        sock_type = SOCK_STREAM;
    } else {
        sock_type = SOCK_DGRAM;
    }

    addrinfo.sin_port = dest_port;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addrinfo.sin_addr, ip, INET_ADDRSTRLEN);
    char *port = itoa(ntohs(addrinfo.sin_port));
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = sock_type;
    getaddrinfo(ip, port, &hints, &res);
    int fd = socket(addrinfo.sin_family, sock_type, 0);
    if (fd < 0) {
        printf("Error creating socket!\n");
        exit(-1);
    }

    connect(fd, res->ai_addr, res->ai_addrlen);
    *out_fd = fd;
}

void generic_close(int *fd) {
    close(*fd);
}

void generic_send(int fd, unsigned char *bytes, size_t byte_len) {
    int bytes_sent = send(fd, bytes, byte_len, 0);
    if (bytes_sent != byte_len) {
        printf("Error! Didn't send enough.\n");
        exit(-1);
    }
}

void generic_recv(int fd, unsigned char *buff, size_t *bufflen) {
    *bufflen = recv(fd, buff, *bufflen, 0);

}

// The internal packet functions are to get around an issue
// where netfilter queue prevents packets between the daemon
// and dns server from being sent.

bool is_internal_packet(struct iphdr *iphdr) {
    return (!is_resolver
            && (iphdr->saddr == our_addr && iphdr->daddr == our_addr));
}

// If we get an internal message that looks like a DNSMessage, then we can assume
// it is passing information between the daemon and either the requester or receiver

bool internal_send(int fd, unsigned char *bytes, size_t byte_len,
                   struct iphdr *iphdr, void *transport_header,
                   uint16_t question_hash, bool is_tcp) {
    DNSMessage *msg;
    int frag_num = 1;
    unsigned char *msgbytes2;
    size_t msgbyte_len2;

    bytes_to_dnsmessage(bytes, byte_len, &msg);
    char *qname = msg->question_section[0]->qname;
    if (((msg->question_section[0])->qname[0]) == '?') {
        msg->question_section[0]->qname = qnamef_2_qname(msg->question_section[0]->qname, &frag_num);
        dnsmessage_to_bytes(msg, &msgbytes2, &msgbyte_len2);
        generic_send(fd, msgbytes2, msgbyte_len2);
    } else {
        generic_send(fd, bytes, byte_len);
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    socklen_t len = sizeof(sin);
    if (getsockname(fd, (struct sockaddr *) &sin, &len) == -1) {
        perror("getsockname");
        exit(-1);
    }

    uint16_t src_port;
    src_port = ntohs(sin.sin_port);
    //    printf("\nsrc port: %d\n", src_port);
    conn_info *ci = malloc(sizeof(conn_info));
    ci->fd = fd;
    ci->is_tcp = is_tcp;
    ci->frag_num = frag_num;
    ci->qname = qname;
    if (is_tcp) {
        ci->transport_header = malloc(sizeof(struct tcphdr));
        memcpy(ci->transport_header, transport_header, sizeof(struct tcphdr));
    } else {
        ci->transport_header = malloc(sizeof(struct udphdr));
        memcpy(ci->transport_header, transport_header, sizeof(struct udphdr));
    }

    ci->iphdr = malloc(sizeof(struct iphdr));
    memcpy(ci->iphdr, iphdr, sizeof(struct iphdr));
    fflush(stdout);
    uintptr_t test;
    uint64_t *question_hash_port = malloc(sizeof(uint64_t));
    memset(question_hash_port, 0, sizeof(uint64_t));
    uint32_t *qh = (uint32_t *) question_hash_port;
    *qh = question_hash;
    *(qh + 1) = src_port;
    if (hashmap_get
            (connection_info.map, question_hash_port, sizeof(uint64_t),
             (uintptr_t * ) & test)) {
        printf("Something is already there...\n");
        fflush(stdout);
        assert(false);
        exit(-1);
    }

    hashmap_set(connection_info.map, question_hash_port, sizeof(uint64_t),
                (uintptr_t) ci);
    if (!hashmap_get
            (connection_info.map, question_hash_port, sizeof(uint64_t),
             (uintptr_t * ) & ci)) {
        printf("Failed to add connection info to hashmap\n");
        fflush(stdout);
        exit(-1);
    }

    return true;
}

uint16_t csum(uint16_t *ptr, int32_t nbytes) {
    int32_t sum;
    uint16_t oddbyte;
    uint16_t answer;

    sum = 0;
    while (nbytes > 1) {
        sum += htons(*ptr);
        ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *) &oddbyte) = *(unsigned char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (int16_t)
    ~sum;

    return answer;
}

bool create_raw_socket(int *fd) {
    int _fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (_fd < 0) {
        return false;
    }

    *fd = _fd;
    return true;
}

bool raw_socket_send(int fd, unsigned char *payload, size_t payload_len,
                     uint32_t saddr, uint32_t daddr, uint16_t sport,
                     uint16_t dport, bool is_tcp) {
    unsigned char *datagram;
    if (is_tcp) {
        datagram =
                malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) +
                       (sizeof(char) * payload_len));
    } else {
        datagram =
                malloc(sizeof(struct iphdr) + sizeof(struct udphdr) +
                       (sizeof(char) * payload_len));
    }

    struct iphdr *iph = (struct iphdr *) datagram;

    unsigned char *data;
    if (is_tcp) {
        data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    } else {
        data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    }

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    if (is_tcp) {
        iph->tot_len =
                sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;
    } else {
        iph->tot_len =
                sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
    }

    iph->tot_len = htons(iph->tot_len);
    memcpy(data, payload, payload_len);
    iph->id = htons(1234);    // This is fine for POC but obviously not for deployment
    iph->frag_off = 0;
    iph->ttl = 255;
    if (is_tcp) {
        iph->protocol = IPPROTO_TCP;
    } else {
        iph->protocol = IPPROTO_UDP;
    }

    iph->check = 0;
    iph->saddr = saddr;
    iph->daddr = daddr;
    // IP checksum
    iph->check = csum((uint16_t *) datagram, sizeof(struct iphdr));
    iph->check = htons(iph->check);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);
    sin.sin_addr.s_addr = daddr;

    unsigned char *tphdr = datagram + sizeof(struct iphdr);
    if (is_tcp) {
        // TCP is not properly implemented. Still need TCP checksum
        struct tcphdr *tcph = (struct tcphdr *) tphdr;
        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = 0;
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 1;
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;
    } else {
        struct udphdr *udph = (struct udphdr *) tphdr;
        udph->source = sport;
        udph->dest = dport;
        udph->check = 0;
        udph->len = htons(payload_len + sizeof(struct udphdr));
    }

    int value = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value))) {
        perror("Error setting IP_HDRINCL");
        exit(-1);
    }

    if (sendto
                (fd, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *) &sin,
                 sizeof(sin)) < 0) {
        perror("raw socket failed to send");
        return false;
    }

    // we don't need to wait for a response for these, so just close the socket.
    close(fd);
    return true;
}

void send_dns_messsge(DNSMessage *msg, struct iphdr *iphdr,
                      void *transport_header, bool is_tcp, bool swap_ip) {
    unsigned char *msgbytes;
    size_t msgbyte_len;
    dnsmessage_to_bytes(msg, &msgbytes, &msgbyte_len);

    int out_fd;
    if (!create_raw_socket(&out_fd)) {
        printf("Failed to make raw socket to send DNS Message \n");
        fflush(stdout);
        ERROR();
    }

    if (swap_ip) {
        if (is_tcp) {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, iphdr->daddr,
                            iphdr->saddr,
                            ((struct tcphdr *) transport_header)->dest,
                            ((struct tcphdr *) transport_header)->source, is_tcp);
        } else {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, iphdr->daddr,
                            iphdr->saddr,
                            ((struct udphdr *) transport_header)->dest,
                            ((struct udphdr *) transport_header)->source, is_tcp);
        }
    } else {
        if (is_tcp) {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, iphdr->saddr,
                            iphdr->daddr,
                            ((struct tcphdr *) transport_header)->source,
                            ((struct tcphdr *) transport_header)->dest, is_tcp);
        } else {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, iphdr->saddr,
                            iphdr->daddr,
                            ((struct udphdr *) transport_header)->source,
                            ((struct udphdr *) transport_header)->dest, is_tcp);
        }
    }
    generic_close(&out_fd);
    free(msgbytes);
}

// this function is identical to the above except for the arguments it takes
void send_dns_messsge2(DNSMessage *msg, uint32_t saddr, uint32_t daddr, uint16_t sport,
                       uint16_t dport, bool is_tcp, bool swap_ip) {
    unsigned char *msgbytes;
    size_t msgbyte_len;
    dnsmessage_to_bytes(msg, &msgbytes, &msgbyte_len);

    int out_fd;
    if (!create_raw_socket(&out_fd)) {
        printf("Failed to make raw socket to send DNS Message \n");
        fflush(stdout);
        ERROR();
    }

    if (swap_ip) {
        if (is_tcp) {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, daddr,
                            saddr,
                            dport,
                            sport, is_tcp);
        } else {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, daddr,
                            saddr,
                            dport,
                            sport, is_tcp);
        }
    } else {
        if (is_tcp) {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, saddr,
                            daddr,
                            sport,
                            dport, is_tcp);
        } else {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, saddr,
                            daddr,
                            sport,
                            dport, is_tcp);
        }
    }
    generic_close(&out_fd);
    free(msgbytes);
}

bool handle_internal_packet(struct nfq_q_handle *qh, uint32_t id,
                            struct iphdr *iphdr, uint64_t *question_hash_port,
                            unsigned char *outbuff, size_t *outbuff_len) {
    assert(is_internal_packet(iphdr));
    uint32_t verdict = NF_ACCEPT;
    if (!nfq_set_verdict(qh, id, verdict, 0, NULL)) {
        printf("Failed to accept internal packet\n");
        fflush(stdout);
        exit(-1);
    }

    // We need to get the file descriptor from a previous cb, so get it from
    // a hashtable based on the dest (original socket's source port)
    // if there is something there, receive it, otherwise just return
    conn_info *ci;
    int fd;
    if (!hashmap_get
            (connection_info.map, question_hash_port, sizeof(uint64_t),
             (uintptr_t * ) & ci)) {
        return false;
    }

    fd = ci->fd;
    struct pollfd ufd;
    memset(&ufd, 0, sizeof(struct pollfd));
    ufd.fd = fd;
    ufd.events = POLLIN;
    int rv = poll(&ufd, 1, 0);
    if (rv == -1) {
        perror("Failed to poll");
        fflush(stdout);
        exit(-1);
    } else if (rv == 0) {
        // This must be an "outgoing" internal message
        // so we just need to accept
        return false;
    } else {
        if (ufd.revents & POLLIN) {
            *outbuff_len = recv(fd, outbuff, *outbuff_len, 0);
            return true;
        } else {
            printf("poll returned on an event we don't care about\n");
            exit(-1);
        }
    }
}

void internal_close(int fd, uint64_t question_hash_port) {
    hashmap_remove(connection_info.map, &question_hash_port,
                   sizeof(uint64_t));
    generic_close(&fd);
}

void refresh_hashmap(hashmap **map);


void responding_thread_start(DNSMessage *imsg, struct iphdr *iphdr,
                             void *transport_hdr, bool is_tcp) {
    // open socket using the same protocol as used for the request
    int fd;
    uint32_t dst_ipaddr = iphdr->daddr;
    uint16_t dst_port;
    if (is_tcp) {
        dst_port = ((struct tcphdr *) transport_hdr)->dest;
    } else {
        dst_port = ((struct udphdr *) transport_hdr)->dest;
    }

    unsigned char *imsg_bytes;
    size_t imsg_size;
    dnsmessage_to_bytes(imsg, &imsg_bytes, &imsg_size);
    uint16_t question_hash;
    if (imsg->qdcount == 1)    /*it should always be one */
    {
        unsigned char *qout;
        size_t qout_size;
        if (imsg->question_section[0]->qname[0] != '?') {
            question_to_bytes(imsg->question_section[0], &qout, &qout_size);
            question_hash = hash_16bit(qout, qout_size);
        } else {
            int frag_num;
            imsg->question_section[0]->qname = qnamef_2_qname(imsg->question_section[0]->qname, &frag_num);
            question_to_bytes(imsg->question_section[0], &qout, &qout_size);
            question_hash = hash_16bit(qout, qout_size);
        }

        //        printf("\nqhash: %d\n", question_hash);
    } else {
        assert(false);
    }

    create_generic_socket(dst_ipaddr, dst_port, is_tcp, &fd);
    internal_send(fd, imsg_bytes, imsg_size, iphdr, transport_hdr,
                  question_hash, is_tcp);
    destroy_dnsmessage(&imsg);
}

/*
returns the size (in bytes) for questions
*/
int size_questions_inner(Question **questions, const int count) {
    size_t size = 0;
    size_t q_len;
    for (int i = 0; i < count; i++) {
        unsigned char *q_bytes;
        question_to_bytes(questions[i], &q_bytes, &q_len);
        free(q_bytes);
        size += q_len;
        printf("\nQuestion %d size: %ld", i, q_len);
    }
    return size;
}

/*
wrapper for size_questions_inner
*/
int size_questions(const DNSMessage *const msg) {
    return size_questions_inner(msg->question_section, msg->qdcount);
}

/*
calculates the size for a given resource record section
calculation changes if is_resolver is set, because in that case, the size needs to be estimated from the given fragment
@param section: target section
@param count: size of section
@param is_resolver: indicates if called from resolver
@param is_additional: indicates if section is additional section (OPT changes)
@param sizes: stores each rr size
@param num_sig_rr, num_dnskey_rr: returns the number of signatures/keys 
@param total_sig_rr, total_dnskey_rr: returns the total number of bytes for signatures/keys 
@param savings: returns savings
*/
int size_section(ResourceRecord **section, const int count, const bool is_resolver, const bool is_additional, int *sizes, int *num_sig_rr, int *num_dnskey_rr, int *total_sig_rr, int *total_dnskey_rr, int *savings) {
    size_t size = 0;
    int alg_sig_size, alg_pk_size;
    for (int i = 0; i < count; i++) {
        // keeps track of the rr_size
        size_t rr_size = 0;
        size_t rr_outlen;
        unsigned char *rrout;
        ResourceRecord *rr = section[i];
        rr_to_bytes(rr, &rrout, &rr_outlen);

        // if resolver, calculate total message size based on known key sizes
        // NOTE: can be slightly of because of variable signature/key size
        // TODO: fix for production
        if (rr->type == RRSIG) {
            printf("\nRRSIG RR found...");
            *num_sig_rr += 1;
            int num_sig_frag_bytes = calc_num_sig_bytes(rr->rdsize, rr->rdata);
            printf("\nnum_sig_bytes: %d", num_sig_frag_bytes);
            if (is_resolver) {
                alg_sig_size = get_alg_sig_pk_size(rr->type, rr->rdata);
                rr_size = rr_outlen - num_sig_frag_bytes + alg_sig_size;
                // use alg_sig_size as estimate
                sizes[i] = alg_sig_size;
                *total_sig_rr += alg_sig_size;
            }
            else {
                rr_size = rr_outlen;
                // complete message so use this
                sizes[i] = num_sig_frag_bytes;
                *total_sig_rr += num_sig_frag_bytes;
            }
        } 
        else if (rr->type == DNSKEY && (rr->rdata[3] != SPHINCS_PLUS_SHA256_128S_ALG)) {
            printf("\nDNSKEY RR found...");
            *num_dnskey_rr += 1;
            // | Flags (2B) | Protocol (1B) | Algorithm (1B) | Key |
            int header_size = 4;
            int num_dnskey_frag_bytes = rr->rdsize - header_size;
            printf("\nnum_dnskey_bytes: %d", num_dnskey_frag_bytes);
            if (is_resolver) {
                alg_pk_size = get_alg_sig_pk_size(rr->type, rr->rdata);
                rr_size = rr_outlen - num_dnskey_frag_bytes + alg_pk_size;                
                // use alg_sig_size as estimate
                sizes[i] = alg_pk_size;
                *total_sig_rr += alg_pk_size;
            }
            else {
                rr_size = rr_outlen;
                // gets ignored for resolvers
                sizes[i] = num_dnskey_frag_bytes;
                *total_dnskey_rr += num_dnskey_frag_bytes;
            }
        } 
        else {
            rr_size = rr_outlen;
            if (!is_additional || rr->type != OPT)
                *savings += rr_outlen;
            // should not get used but store just in case
            sizes[i] = rr_size;
        }
        printf("\nAnswer %d size: %ld", i, rr_outlen);
        size += rr_size;
    }
    return size;
}


/*
gets the start and end index for a given fragment
has to be calculated for every fragment and RR combination
needs to be done because each rr sig/key can have slightly different key sizes
@param frag_nr: fragment
@param alg_size: total size of key or signature
@param num_required_frags: total number of fragments
@param can_send_1: can send in first fragment
@param can_send: can send in 2..n fragments
@param total_pk_sig_bytes_per_frag: total amount of sig/pk bytes to be sent
@param rr_pk_sig_count: total number of sig and key rr's
@param start_idx, end_idx: start and end index for the given rr-fragment combination
*/
void get_frag_index(const int frag_nr, const int num_required_frags, const int alg_size, const int can_send_1, const int can_send, const int total_pk_sig_bytes_per_frag, const int rr_pk_sig_count, int *start_idx, int *end_idx) {
    int rem_space_per_frag, can_send_additional, rem_space_per_frag_1, can_send_additional_1;
    int num_bytes_to_send = alg_size / num_required_frags;
    rem_space_per_frag_1 = can_send_1 - total_pk_sig_bytes_per_frag; 
    rem_space_per_frag = can_send - total_pk_sig_bytes_per_frag;
    can_send_additional_1 = rem_space_per_frag_1 / rr_pk_sig_count;
    can_send_additional = rem_space_per_frag / rr_pk_sig_count;
    printf("\nrem_space_per_frag_1: %d", rem_space_per_frag_1);
    printf("\ncan_send_additional_1: %d", can_send_additional_1);
    printf("\nrem_space_per_frag: %d", rem_space_per_frag);
    printf("\ncan_send_additional: %d", can_send_additional);

    /*
    0 ... num_bytes_to_send + can_send_additional_1 - 1
    num_bytes_to_send + can_send_additional_1 ... num_bytes_to_send + can_send_additional_1 - 1 + num_bytes_to_send + can_send_additional
    num_bytes_to_send + can_send_additional_1 + num_bytes_to_send + can_send_additional ... num_bytes_to_send + can_send_additional_1 - 1 + 2 * (num_bytes_to_send + can_send_additional)

    0 ... num_bytes_to_send + can_send_additional_1 - 1
    num_bytes_to_send + can_send_additional_1 ... num_bytes_to_send + can_send_additional + num_bytes_to_send + can_send_additional_1 - 1
    num_bytes_to_send + can_send_additional_1 + num_bytes_to_send + can_send_additional ... 2 * (num_bytes_to_send + can_send_additional) + num_bytes_to_send + can_send_additional_1 - 1
    seems to work
    */
    *end_idx = (frag_nr - 1) * (num_bytes_to_send + can_send_additional) + num_bytes_to_send + can_send_additional_1 - 1;
    *start_idx = frag_nr == 1 ? 0 : *end_idx - (num_bytes_to_send + can_send_additional) + 1;
    // it is possible that one RR is sent in f.e. 3 fragments 
    // while other RR use 4 --> remaining space is evenly distributed
    // but RR sizes are not the same
    // NOTE: unsure if completely correct
    if (*end_idx > (alg_size - 1) || frag_nr == num_required_frags) {
        *end_idx = alg_size - 1;
    }
    assert(frag_nr != num_required_frags || *end_idx + 1 == alg_size);

    printf("\nstart idx: %d, end idx: %d", *start_idx, *end_idx);
}

/*
calculates the message size
two scenarios:
1. internal message from bind9   : just use message size
2. external fragment from daemon : calculate full message size
returns all rrsizes for all sections
*/
size_t calc_message_size(const DNSMessage *const msg, const bool is_resolver, int **answer_sizes, int **authoritative_sizes, int **additional_sizes, int *num_sig_rr, int *num_dnskey_rr, int *total_sig_rr, int *total_dnskey_rr, int *savings) {
    printf("\nParsing DNS Message...");

    // header
    size_t msgsize = DNSHEADERSIZE;
    printf("\nCurrent size: %ld", msgsize);
    // Question Section
    msgsize += size_questions(msg);
    printf("\nCurrent size: %ld", msgsize);
    // Answer Section
    *answer_sizes = malloc(msg->ancount * sizeof(int));
    msgsize += size_section(msg->answers_section, msg->ancount, is_resolver, false, *answer_sizes, num_sig_rr, num_dnskey_rr, total_sig_rr, total_dnskey_rr, savings);
    printf("\nCurrent size: %ld", msgsize);
    // Authoritative Section
    *authoritative_sizes = malloc(msg->nscount * sizeof(int));
    msgsize += size_section(msg->authoritative_section, msg->nscount, is_resolver, false, *authoritative_sizes, num_sig_rr, num_dnskey_rr, total_sig_rr, total_dnskey_rr, savings);
    printf("\nCurrent size: %ld", msgsize);
    // Additional Section
    *additional_sizes = malloc(msg->arcount * sizeof(int));
    msgsize += size_section(msg->additional_section, msg->arcount, is_resolver, true, *additional_sizes, num_sig_rr, num_dnskey_rr, total_sig_rr, total_dnskey_rr, savings);
    printf("\nCurrent size: %ld", msgsize);
    return msgsize;
}

/*
calculates the number of fragments based on msgsize, total_sig_pk_bytes, savings, and MAX_UDP
*/
int calculate_fragments(const int msgsize, int total_sig_pk_bytes, const int savings, int *can_send_1, int *can_send) {
    int num_fixed_bytes = msgsize - total_sig_pk_bytes;
    printf("\nnum_fixed_bytes: %d", num_fixed_bytes);
    assert(MAXUDP > num_fixed_bytes); // should be true
    *can_send = MAXUDP - num_fixed_bytes;
    *can_send_1 = *can_send;

    int qname_overhead = 4;     // ?fragnum? overhead. Assuming fragnum to be at most 2 digits.
    int num_required_frags = 0;

    while (total_sig_pk_bytes > 0) {
        total_sig_pk_bytes -= *can_send;
        if (num_required_frags == 0) {
            *can_send += savings;
            *can_send -= qname_overhead;
        }
        num_required_frags++;
    }
    return num_required_frags;
}


/*
create the fragments for a given section
*/
uint16_t create_fragments(ResourceRecord **section, ResourceRecord **out_section, const int count, const int frag_nr, const int num_required_frags, const int *const sizes, const int can_send_1, const int can_send, const int total_sig_pk_bytes_per_frag, const int rr_pk_sig_count, const bool is_additional, int *savings) {
    // keep track of new rr count
    uint16_t new_count = 0;
    int start_idx, end_idx;   
    for (int i = 0; i < count; i++) {
        ResourceRecord *rr = section[i];
        // only do this for the additional section
        if (is_additional && rr->type == OPT) {
            clone_rr(rr, out_section + new_count);
            new_count++;
        }
        else if (rr->type == RRSIG || (rr->type == DNSKEY && (rr->rdata[3] != SPHINCS_PLUS_SHA256_128S_ALG))) {    
            get_frag_index(frag_nr, num_required_frags, sizes[i], can_send_1, can_send, total_sig_pk_bytes_per_frag, rr_pk_sig_count, &start_idx, &end_idx);
            ResourceRecord *rr_fragment;
            // should still work because start_idx and end_idx match with rr->type
            create_rr_f(&rr_fragment, rr->name, rr->name_bytes,
                        rr->name_byte_len, rr->type, rr->clas, rr->ttl,
                        rr->rdsize, rr->rdata, start_idx, end_idx, start_idx, end_idx, sizes[i]);
            clone_rr(rr_fragment, out_section + new_count);
            new_count++;
        } 
        else {
            if (frag_nr > 1) {
                unsigned char *rrout;
                size_t rr_outlen;
                rr_to_bytes(rr, &rrout, &rr_outlen);
                *savings += rr_outlen;
            } 
            else {
                clone_rr(rr, out_section + new_count);
                new_count++;
            }
        }
    }
    return new_count;
}


/*
does the following:
1. calculates the number of fragments needed based on msg
2. if is_resolver = false --> add the fragments to cache
*/
int prepare_fragments(DNSMessage *const msg, const bool is_resolver) {
    // vars
    int num_dnskey_rr = 0;
    int num_sig_rr = 0;
    int total_sig_rr = 0;
    int total_dnskey_rr = 0;
    int savings = 0; // space taken by redundant RRs

    // store rr sizes for each section
    int *answer_sizes, *authoritative_sizes, *additional_sizes;

    // calculate message size
    size_t msgsize = calc_message_size(msg, is_resolver, &answer_sizes, &authoritative_sizes, &additional_sizes, &num_sig_rr, &num_dnskey_rr, &total_sig_rr, &total_dnskey_rr, &savings);
    // print information
    printf("\nTotal DNS Message size: %ld", msgsize);
    printf("\nnr. sig: %d, total size: %d", num_sig_rr, total_sig_rr);
    printf("\nnr. keys: %d, total size: %d", num_dnskey_rr, total_dnskey_rr);
    int total_sig_pk_bytes = total_sig_rr + total_dnskey_rr;
    int rr_pk_sig_count = num_sig_rr + num_dnskey_rr;
    printf("\ntotal_sig_pk_bytes: %d", total_sig_pk_bytes);
    printf("\nMAXUDP: %d", MAXUDP);
    printf("\nSavings: %d", savings);

    // calculate nr of fragments
    int can_send_1, can_send;
    int num_required_frags = calculate_fragments(msgsize, total_sig_pk_bytes, savings, &can_send_1, &can_send);
    printf("\nnum_required_frags: %d", num_required_frags);  
    
    // resolvers don't do this
    if (!is_resolver) {
        printf("\ncan_send (1st frag): %d", can_send_1);
        printf("\ncan_send (rest frags): %d", can_send);

        // what happens if not divisible?
        // calculate bytes per fragment
        int num_sig_bytes_per_frag = total_sig_rr / num_required_frags;
        printf("\nnum_sig_bytes_per_frag: %d", num_sig_bytes_per_frag);
        int num_pk_bytes_per_frag = total_dnskey_rr / num_required_frags;
        printf("\nnum_pk_bytes_per_frag: %d", num_pk_bytes_per_frag);
        int total_sig_pk_bytes_per_frag = num_sig_bytes_per_frag + num_pk_bytes_per_frag;

        uintptr_t out;
        ResponderMsgStore *store = malloc(sizeof(ResponderMsgStore));
        uint16_t *id = malloc(sizeof(uint16_t));
        *id = msg->identification;

        if (!hashmap_get(responder_state, id, sizeof(uint16_t), &out)) {
            printf("\nAdding full msg to cache...");
            clone_dnsmessage(msg, &(store->m_arr[0]));
            store->num_required_frags = num_required_frags;
        }

        for (int i = 1; i <= num_required_frags; i++) {

            printf("\n\nFragment %d", i);
            printf("\nFragmenting DNS Message....");

            int savings = 0;

            DNSMessage *m;
            clone_dnsmessage(msg, &m);

            // are these records freed?
            Question **question_section = malloc(sizeof(Question * ) * msg->qdcount);
            memcpy(question_section, msg->question_section, sizeof(Question * ) * msg->qdcount);
            ResourceRecord **answers_section = malloc(sizeof(ResourceRecord * ) * m->ancount);
            ResourceRecord **authoritative_section = malloc(sizeof(ResourceRecord * ) * m->nscount);
            ResourceRecord **additional_section = malloc(sizeof(ResourceRecord * ) * m->arcount);

            uint16_t qdcount = m->qdcount;
            uint16_t ancount = create_fragments(m->answers_section, answers_section, m->ancount, i, num_required_frags, answer_sizes, can_send_1, can_send, total_sig_pk_bytes_per_frag, rr_pk_sig_count, false, &savings);
            uint16_t nscount = create_fragments(m->authoritative_section, authoritative_section, m->nscount, i, num_required_frags, authoritative_sizes, can_send_1, can_send, total_sig_pk_bytes_per_frag, rr_pk_sig_count, false, &savings);   
            uint16_t arcount = create_fragments(m->additional_section, additional_section, m->arcount, i, num_required_frags, additional_sizes, can_send_1, can_send, total_sig_pk_bytes_per_frag, rr_pk_sig_count, true, &savings);

            printf("\nSavings: %d", savings);
            printf("\nAdding Fragment %d to cache...\n", i);
            m->flags = m->flags | (1 << 9);    // Mark as Truncated
            DNSMessage *tmp;
            create_dnsmessage(&tmp, m->identification, m->flags, qdcount, ancount, nscount, arcount,
                            question_section, answers_section, authoritative_section, additional_section);
            clone_dnsmessage(tmp, &(store->m_arr[i]));
            destroy_dnsmessage(&m);
            destroy_dnsmessage(&tmp);
        }
        // using just ID as key is ok for POC but not for deployment
        hashmap_set(responder_state, id, sizeof(uint16_t), (uintptr_t) store);
        // free up memory
        // free(id);
        free(answer_sizes);
        free(authoritative_sizes);
        free(additional_sizes);
    }
    return num_required_frags;

}

DNSMessage *fragment_dns_message(DNSMessage *msg, size_t MAXUDP,
                                 int frag_num, char *qnamef) {
    printf("\nFragmenting DNS Message....");
    printf("\nRequested fragment number: %d", frag_num);

    uint16_t *id = malloc(sizeof(uint16_t));
    *id = msg->identification;

    DNSMessage *m;
    clone_dnsmessage(msg, &m);

    ResponderMsgStore *store;
    if (hashmap_get(responder_state, id, sizeof(uint16_t), (uintptr_t * ) & store)) {
        printf("\nMsg found in cache!");
    } else {
        printf("\nMsg not in cache...");
        //calc_num_required_frags(m, frag_num, 0);
        prepare_fragments(m, false);
        hashmap_get(responder_state, id, sizeof(uint16_t), (uintptr_t * ) & store);
    }

    DNSMessage *m2;
    if (frag_num > store->num_required_frags) {
        printf("\nExtra fragment request. Only %d fragments are required.",
               store->num_required_frags);
        printf("\nSending FORMERR...");

        Question **question_section = malloc(sizeof(Question * ));
        ResourceRecord **additional_section = malloc(sizeof(ResourceRecord * ));

        clone_question(msg->question_section[0], question_section);
        ResourceRecord *rr = msg->additional_section[msg->arcount - 1];
        clone_rr(rr, additional_section);
        create_dnsmessage(&m2, msg->identification, msg->flags, 1, 0, 0, 1,
                          question_section, NULL, NULL, additional_section);

        m2->flags = m2->flags | (1 << 0); // Mark as RCODE->FORMERR
        m2->flags = m2->flags | (1 << 9);    // Mark as Truncated
    } else {
        clone_dnsmessage(store->m_arr[frag_num], &m2);;
    }

    m2->question_section[0]->qname = qnamef;   // replace with qname of the query

    return m2;
}

void responding_thread_end(struct iphdr *iphdr, void *transport_hdr, bool is_tcp,
                           unsigned char *recvd, size_t recvd_len,
                           uint64_t *question_hash_port, int fd, int frag_num,
                           char *qname) {
    internal_close(fd, *question_hash_port);
    DNSMessage *recvd_msg;
    DNSMessage *frag_msg;

    if (bytes_to_dnsmessage(recvd, recvd_len, &recvd_msg) != 0) {
        assert("Failed to build dnsmessage from response to imsg" == false);
    }

    printf("\nFull DNS Message from bind9:\n");
    if (debug)
        dnsmessage_to_string(recvd_msg);

    if (recvd_len <= MAXUDP) {
        printf("DNS Message within MAXUDP Limit. No need to fragment.\n");
        frag_msg = recvd_msg;
    } else {
        printf("DNS Message exceeds MAXUDP Limit!\n");
        // Finally we can make our new DNSMessage and send it back to who we got it from.
        frag_msg = fragment_dns_message(recvd_msg, MAXUDP, frag_num, qname);
        destroy_dnsmessage(&recvd_msg);
    }

    fd = -1;
    unsigned char *msg_bytes;
    size_t byte_len;
    dnsmessage_to_bytes(frag_msg, &msg_bytes, &byte_len);
    destroy_dnsmessage(&frag_msg);
    create_raw_socket(&fd);
    if (is_tcp) {
        raw_socket_send(fd, msg_bytes, byte_len, iphdr->daddr, iphdr->saddr,
                        ((struct tcphdr *) transport_hdr)->dest,
                        ((struct tcphdr *) transport_hdr)->source, is_tcp);
    } else {
        if (byte_len > MAXUDP) {
            printf("byte_len: %lu, MAXUDP: %u, difference: %lu\n", byte_len,
                   MAXUDP, byte_len - (size_t) MAXUDP);
            assert(byte_len <= MAXUDP);
        }

        raw_socket_send(fd, msg_bytes, byte_len, iphdr->daddr, iphdr->saddr,
                        ((struct udphdr *) transport_hdr)->dest,
                        ((struct udphdr *) transport_hdr)->source, is_tcp);
    }

    close(fd);
}

void *sendQueryThread(void *ptr) {
    if (ALG == 2) {
        // this is to get around an issue with internal packet implementation
        // at the moment, it cannot handle 22+ fragment requests of SPHINCS+
        // so we wait for responder to build its fragment cache
        printf("\nSleep for 100 ms before sending fragment requests...\n");
        usleep(100000);
    }

    ToSendDNSMessage *mystruct = (ToSendDNSMessage *) ptr;

    for (int i = 2; i <= mystruct->m_arr_size; i++) {
        send_dns_messsge2(mystruct->m_arr[i], mystruct->saddr, mystruct->daddr, mystruct->sport, mystruct->dport,
                          mystruct->is_tcp,
                          mystruct->swap_ip);
    }
    return NULL;
}

uint32_t process_dns_message(struct nfq_q_handle *qh, uint32_t id,
                             unsigned char *payload, size_t payloadLen,
                             struct iphdr *iphdr, void *transport_header, bool is_tcp, bool BYPASS) {
    unsigned char *pkt_content;
    DNSMessage *msg;

    uint32_t saddr = iphdr->saddr;
    uint32_t daddr = iphdr->daddr;
    uint16_t sport;
    uint16_t dport;
    uint16_t sport_;
    uint16_t dport_;

    if (is_tcp) {
        sport = ((struct tcphdr *) transport_header)->source;
        sport_ = sport;
        sport = ntohs(sport);
        dport = ((struct tcphdr *) transport_header)->dest;
        dport_ = dport;
        dport = ntohs(dport);
    } else {
        sport = ((struct udphdr *) transport_header)->source;
        sport_ = sport;
        sport = ntohs(sport);
        dport = ((struct udphdr *) transport_header)->dest;
        dport_ = dport;
        dport = ntohs(dport);
    }

    if (is_tcp)
        printf("\n* Got IP Packet via TCP *\n");
    else
        printf("\n* Got IP Packet via UDP *\n");

    print_ip_port(saddr, daddr, sport, dport);

    size_t msgSize = payloadLen;
    if (is_tcp) {
        pkt_content = payload + sizeof(struct tcphdr) + sizeof(struct iphdr);
        msgSize -= sizeof(struct tcphdr) + sizeof(struct iphdr);
    } else {
        pkt_content = payload + sizeof(struct udphdr) + sizeof(struct iphdr);
        msgSize -= sizeof(struct udphdr) + sizeof(struct iphdr);
    }

    if (BYPASS)
        return NF_ACCEPT;

    if (debug) {
        if (!looks_like_dnsmessage(pkt_content, msgSize)) {
            printf("[Warning]This doesn't look like a dnsmessage\n");
            fflush(stdout);
            return NF_ACCEPT;
        }
    }

    int rc = bytes_to_dnsmessage(pkt_content, msgSize, &msg);
    if (rc != 0) {
        printf("[Error]Failed to convert bytes to dns_message\n");
        ERROR();
    }

    /*
    Either a bind9 response or any other internal message
    We can just accept (ignore) other messages
    */
    if (is_internal_packet(iphdr)) {
        printf("<Internal Packet > \n");
        size_t outbuff_len = 65355;    // Need to account for large messages because of SPHINCS+
        unsigned char outbuff[outbuff_len];
        uint64_t *question_hash_port = malloc(sizeof(uint64_t));
        memset(question_hash_port, 0, sizeof(uint64_t));
        
        assert(msg->qdcount == 1);
        unsigned char *qout;
        size_t qout_size;
        question_to_bytes(msg->question_section[0], &qout, &qout_size);
        uint32_t *question_hash = (uint32_t *) question_hash_port;
        *question_hash = hash_16bit(qout, qout_size);
        *(question_hash + 1) = dport;
        

        if (handle_internal_packet(qh, id, iphdr, question_hash_port, outbuff, &outbuff_len)
            && dport != 53) {
            conn_info *ci;
            if (!hashmap_get(connection_info.map, question_hash_port, sizeof(uint64_t), (uintptr_t * ) & ci)) {
                printf("Failed to get ci\n");
                fflush(stdout);
                return NF_ACCEPT;
            }
            responding_thread_end(ci->iphdr, ci->transport_header, ci->is_tcp,
                                  outbuff, outbuff_len, question_hash_port,
                                  ci->fd, ci->frag_num, ci->qname);
        } else {
            return NF_ACCEPT;
        }
        return 0xFFFF;
    }

    if (dport != 53 && sport != 53) {
        printf("[Warning]Non-standard dns port. Likely not dns message so ignoring.\n");
        return NF_ACCEPT;
    }

    /* DNS MESSAGE IS A QUERY */
    if (is_query(msg)) {
        // If we are sending the packet, and the packet
        // is a query, then there is nothing for us to
        // do yet...

        if (saddr == our_addr && dport == 53) {
            if (((msg->question_section[0])->qname[0]) == '?') {
                printf("Resolver : Send DNS Query \n");
                if (debug)
                    dnsmessage_to_string(msg);
                return NF_ACCEPT;
            }

            // drop AAAA requests
            if (((msg->question_section[0])->qtype) == 28) {
                return NF_DROP;
            }

            printf("Resolver : Send DNS Query \n");
            if (debug)
                dnsmessage_to_string(msg);


            uint16_t *id = malloc(sizeof(uint16_t));
            *id = msg->identification;

            uintptr_t out;
            if (!hashmap_get(requester_state, id, sizeof(uint16_t), &out)) {
                RequesterMsgStore *store = malloc(sizeof(RequesterMsgStore));
                clone_dnsmessage(msg, &(store->m_arr[0]));

                ToSendDNSMessage *tosendPTR;
                tosendPTR = (ToSendDNSMessage *) malloc(sizeof(ToSendDNSMessage));
                tosendPTR->saddr = saddr;
                tosendPTR->daddr = daddr;
                tosendPTR->sport = sport_;
                tosendPTR->dport = dport_;
                tosendPTR->is_tcp = is_tcp;
                tosendPTR->swap_ip = 0;

                // num_required_frags = 1 (original query) + num extra queries

                if (MODE == 2) {
                    if (ALG == 0) { // FALCON512
                        if (msg->question_section[0]->qtype == DNSKEY)
                            store->num_required_frags = 3;
                        else if (msg->question_section[0]->qtype == 1 && msg->question_section[0]->qname[0] != '_')
                            store->num_required_frags = 3;
                    } else if (ALG == 1) { // DILITHIUM2
                        if (msg->question_section[0]->qtype == DNSKEY)
                            store->num_required_frags = 7;
                        else if (msg->question_section[0]->qtype == 1) {
                            if (msg->question_section[0]->qname[0] == '_') // qname minimization, expecting referral
                                store->num_required_frags = 3;
                            else
                                store->num_required_frags = 7;
                        } else
                            store->num_required_frags = 3;
                    } else if (ALG == 2) { // SPHINCS+
                        if (msg->question_section[0]->qtype == DNSKEY)
                            store->num_required_frags = 15;
                        else if (msg->question_section[0]->qtype == 1) {
                            if (msg->question_section[0]->qname[0] == '_')
                                store->num_required_frags = 7;
                            else
                                store->num_required_frags = 23;
                        } else
                            store->num_required_frags = 7;
                    } else if (ALG == 3) { // P256_FALCON512
                        if (msg->question_section[0]->qtype == DNSKEY)
                            store->num_required_frags = 4;
                        else if (msg->question_section[0]->qtype == 1 && msg->question_section[0]->qname[0] != '_')
                            store->num_required_frags = 4;
                    } else if (ALG == 4) { // P256_DILITHIUM2
                        if (msg->question_section[0]->qtype == DNSKEY)
                            store->num_required_frags = 7;
                        else if (msg->question_section[0]->qtype == 1) {
                            if (msg->question_section[0]->qname[0] == '_') // qname minimization, expecting referral
                                store->num_required_frags = 3;
                            else
                                store->num_required_frags = 7;
                        } else
                            store->num_required_frags = 3;
                    } else if (ALG == 5) { // MAYO
                        if (msg->question_section[0]->qtype == DNSKEY)
                            store->num_required_frags = 4;
                        else if (msg->question_section[0]->qtype == 1 && msg->question_section[0]->qname[0] != '_')
                            store->num_required_frags = 3;
                    } 
                    for (int i = 2; i <= store->num_required_frags; i++) {
                        clone_dnsmessage(msg, &(tosendPTR->m_arr[i]));
                        tosendPTR->m_arr[i]->question_section[0]->qname = qname_2_qnamef(
                                msg->question_section[0]->qname, i);
                    }
                    tosendPTR->m_arr_size = store->num_required_frags;
                    pthread_t thread_id;
                    pthread_create(&thread_id, NULL, sendQueryThread, (void *) tosendPTR);
                }
                store->num_stored_frags = 0;
                hashmap_set(requester_state, id, sizeof(uint16_t), (uintptr_t) store);
            }

            return NF_ACCEPT;
        } else if (daddr == our_addr && dport == 53) {
            printf("Name Server : Receive DNS Query \n");
            if (debug)
                dnsmessage_to_string(msg);

            if (!is_resolver) {
                uint16_t *id = malloc(sizeof(uint16_t));
                *id = msg->identification;

                ResponderMsgStore *store;
                if (hashmap_get(responder_state, id, sizeof(uint16_t), (uintptr_t * ) & store)) {
                    printf("\nResponse found in cache!");
                    DNSMessage *resp;
                    if (((msg->question_section[0])->qname[0]) == '?') {
                        int frag_num;
                        qnamef_2_qname(msg->question_section[0]->qname, &frag_num);
                        printf("\nRequest for fragment %d", frag_num);
                        if (frag_num > store->num_required_frags) {
                            printf("\nExtra fragment request. Only %d fragments are required.",
                                   store->num_required_frags);
                            resp = msg;
                            resp->flags = resp->flags | (1 << 0); // Mark as RCODE->FORMERR
                            resp->flags = resp->flags | (1 << 9);    // Mark as Truncated
                            printf("\nSending FORMERR...");
                        } else {
                            resp = store->m_arr[frag_num];
                            resp->question_section[0]->qname = msg->question_section[0]->qname;
                            printf("\nSending cached response...");
                        }
                    } else {
                        printf("\nRequest for fragment %d", 1);
                        resp = store->m_arr[1];
                    }
                    send_dns_messsge(resp, iphdr, transport_header, is_tcp, 1);
                } else {
                    printf("\nResponse not in cache...");
                    printf("\nName Server : Make internal query to bind9");
                    DNSMessage *iquery;
                    construct_intermediate_message(msg, &iquery);
                    responding_thread_start(iquery, iphdr, transport_header, is_tcp);
                }
                return NF_DROP;
            } else {
                return NF_ACCEPT;
            }
        }
    }

        /* DNS MESSAGE IS A RESPONSE */
    else {
        if (daddr == our_addr && sport == 53) {
            printf("Resolver : Receive DNS Response \n");
            if (debug)
                dnsmessage_to_string(msg);

            if (is_truncated(msg)) {
                printf("\nTC DNS response....");
                uint16_t id = msg->identification;

                if (msg->question_section[0]->qname[0] != '?' && MODE != 2) {
                    printf("\nFragment number: 1");
                    RequesterMsgStore *store;
                    if (hashmap_get(requester_state, &id, sizeof(uint16_t), (uintptr_t * ) & store)) {
                        printf("\nStoring fragment...");
                        clone_dnsmessage(msg, &(store->m_arr[1]));
                        // store->num_required_frags = calc_num_required_frags(msg, 1, 1);
                        store->num_required_frags = prepare_fragments(msg, true);
                        store->num_stored_frags += 1;
                        printf("\nNeed %d more fragments...",
                               store->num_required_frags - store->num_stored_frags);
                    }
                    if (MODE == 1) {
                        for (int i = 2; i <= store->num_required_frags; i++) {
                            printf("\nSending fragment %d query...", i);
                            DNSMessage *m;
                            clone_dnsmessage(store->m_arr[0], &m);
                            m->question_section[0]->qname = qname_2_qnamef(m->question_section[0]->qname, i);
                            send_dns_messsge(m, iphdr, transport_header, is_tcp, 1);
                            destroy_dnsmessage(&m);
                        }
                    } else if (MODE == 0) {
                        printf("\nSending fragment %d query...", 2);
                        DNSMessage *m;
                        clone_dnsmessage(store->m_arr[0], &m);
                        m->question_section[0]->qname = qname_2_qnamef(m->question_section[0]->qname, 2);
                        send_dns_messsge(m, iphdr, transport_header, is_tcp, 1);
                        destroy_dnsmessage(&m);
                    }
                } else {
                    if (MODE == 0) {
                        int frag_num;
                        qnamef_2_qname(msg->question_section[0]->qname, &frag_num);
                        printf("\nFragment number: %d", frag_num);
                        RequesterMsgStore *store;
                        if (hashmap_get(requester_state, &id, sizeof(uint16_t), (uintptr_t * ) & store)) {
                            printf("\nCombining DNS fragments...");

                            for (int i = 0; i < store->m_arr[1]->ancount; i++) {
                                ResourceRecord *rr1 = store->m_arr[1]->answers_section[i];

                                for (int j = 0; j < msg->ancount; j++) {
                                    ResourceRecord *rr2 = msg->answers_section[j];

                                    if ((rr1->type == RRSIG && rr2->type == RRSIG) ||
                                        (rr1->type == DNSKEY && rr2->type == DNSKEY &&
                                         (rr1->rdata[3] !=
                                          SPHINCS_PLUS_SHA256_128S_ALG) &&
                                         (rr2->rdata[3] !=
                                          SPHINCS_PLUS_SHA256_128S_ALG))) {
                                        ResourceRecord *rr_combined;
                                        if (combine_rr(&rr_combined, rr1->name,
                                                       rr1->name_bytes,
                                                       rr1->name_byte_len, rr1->type,
                                                       rr1->clas, rr1->ttl,
                                                       rr1->rdsize, rr1->rdata,
                                                       rr2->rdsize, rr2->rdata) == 1)
                                            continue;
                                        free(store->m_arr[1]->answers_section[i]);
                                        store->m_arr[1]->answers_section[i] = malloc(sizeof(rr_combined));
                                        clone_rr(rr_combined, &(store->m_arr[1]->answers_section[i]));
                                        break;
                                    }
                                }
                            }

                            for (int i = 0; i < store->m_arr[1]->nscount; i++) {
                                ResourceRecord *rr1 = store->m_arr[1]->authoritative_section[i];

                                for (int j = 0; j < msg->nscount; j++) {
                                    ResourceRecord *rr2 = msg->authoritative_section[j];

                                    if ((rr1->type == RRSIG && rr2->type == RRSIG) ||
                                        (rr1->type == DNSKEY && rr2->type == DNSKEY &&
                                         (rr1->rdata[3] !=
                                          SPHINCS_PLUS_SHA256_128S_ALG) &&
                                         (rr2->rdata[3] !=
                                          SPHINCS_PLUS_SHA256_128S_ALG))) {
                                        ResourceRecord *rr_combined;
                                        if (combine_rr(&rr_combined, rr1->name,
                                                       rr1->name_bytes,
                                                       rr1->name_byte_len, rr1->type,
                                                       rr1->clas, rr1->ttl,
                                                       rr1->rdsize, rr1->rdata,
                                                       rr2->rdsize, rr2->rdata) == 1)
                                            continue;
                                        free(store->m_arr[1]->authoritative_section[i]);
                                        store->m_arr[1]->authoritative_section[i] = malloc(
                                                sizeof(rr_combined));
                                        clone_rr(rr_combined,
                                                 &(store->m_arr[1]->authoritative_section[i]));
                                        break;
                                    }
                                }
                            }

                            for (int i = 0; i < store->m_arr[1]->arcount; i++) {
                                ResourceRecord *rr1 = store->m_arr[1]->additional_section[i];

                                for (int j = 0; j < msg->arcount; j++) {
                                    ResourceRecord *rr2 = msg->additional_section[j];

                                    if ((rr1->type == RRSIG && rr2->type == RRSIG) ||
                                        (rr1->type == DNSKEY && rr2->type == DNSKEY &&
                                         (rr1->rdata[3] !=
                                          SPHINCS_PLUS_SHA256_128S_ALG) &&
                                         (rr2->rdata[3] !=
                                          SPHINCS_PLUS_SHA256_128S_ALG))) {
                                        ResourceRecord *rr_combined;
                                        if (combine_rr(&rr_combined, rr1->name,
                                                       rr1->name_bytes,
                                                       rr1->name_byte_len, rr1->type,
                                                       rr1->clas, rr1->ttl,
                                                       rr1->rdsize, rr1->rdata,
                                                       rr2->rdsize, rr2->rdata) == 1)
                                            continue;
                                        free(store->m_arr[1]->additional_section[i]);
                                        store->m_arr[1]->additional_section[i] = malloc(
                                                sizeof(rr_combined));
                                        clone_rr(rr_combined, &(store->m_arr[1]->additional_section[i]));
                                        break;
                                    }
                                }
                            }

                            if (frag_num == store->num_required_frags) {
                                printf("\nDNS Message Complete!\n");
                                store->m_arr[1]->flags =
                                        store->m_arr[1]->flags & (65023 << 0);    // Mark as Un-Truncated
                                printf("\nSending Full DNS Message to bind9... \n");
                                send_dns_messsge(store->m_arr[1], iphdr, transport_header, is_tcp, 0);
                            } else {
                                printf("\nUpdated DNS Message: \n");
                                if (debug)
                                    dnsmessage_to_string(store->m_arr[1]);
                                printf("\nSending fragment %d Query...", frag_num + 1);
                                DNSMessage *m;
                                clone_dnsmessage(store->m_arr[0], &m);
                                m->question_section[0]->qname = qname_2_qnamef(m->question_section[0]->qname,
                                                                               frag_num + 1);
                                send_dns_messsge(m, iphdr, transport_header, is_tcp, 1);
                                destroy_dnsmessage(&m);
                            }
                        }
                    } else if (MODE == 1 || MODE == 2) {
                        int frag_num;
                        if (msg->question_section[0]->qname[0] != '?')
                            frag_num = 1;
                        else
                            qnamef_2_qname(msg->question_section[0]->qname, &frag_num);
                        printf("\nFragment number: %d", frag_num);
                        RequesterMsgStore *store;
                        if (hashmap_get(requester_state, &id, sizeof(uint16_t), (uintptr_t * ) & store)) {
                            if (msg->flags & 1 << 0) {
                                printf("\nFORMERR Response!");
                                store->num_required_frags -= 1;
                            } else {
                                printf("\nStoring fragment...");
                                clone_dnsmessage(msg, &(store->m_arr[frag_num]));
                                store->num_stored_frags += 1;
                            }
                            printf("\nNeed %d more fragments...",
                                   store->num_required_frags - store->num_stored_frags);

                            if (store->num_stored_frags == store->num_required_frags) {
                                printf("\nGot all the fragments! Start combining....");

                                for (int i = 2; i <= store->num_required_frags; i++) {
                                    msg = store->m_arr[i];
                                    printf("\nCombining DNS fragment %d...", i);

                                    for (int i = 0; i < store->m_arr[1]->ancount; i++) {
                                        ResourceRecord *rr1 = store->m_arr[1]->answers_section[i];

                                        for (int j = 0; j < msg->ancount; j++) {
                                            ResourceRecord *rr2 = msg->answers_section[j];

                                            if ((rr1->type == RRSIG && rr2->type == RRSIG) ||
                                                (rr1->type == DNSKEY && rr2->type == DNSKEY &&
                                                 (rr1->rdata[3] !=
                                                  SPHINCS_PLUS_SHA256_128S_ALG) &&
                                                 (rr2->rdata[3] !=
                                                  SPHINCS_PLUS_SHA256_128S_ALG))) {
                                                ResourceRecord *rr_combined;
                                                if (combine_rr(&rr_combined, rr1->name,
                                                               rr1->name_bytes,
                                                               rr1->name_byte_len, rr1->type,
                                                               rr1->clas, rr1->ttl,
                                                               rr1->rdsize, rr1->rdata,
                                                               rr2->rdsize, rr2->rdata) == 1)
                                                    continue;
                                                free(store->m_arr[1]->answers_section[i]);
                                                store->m_arr[1]->answers_section[i] = malloc(
                                                        sizeof(rr_combined));
                                                clone_rr(rr_combined,
                                                         &(store->m_arr[1]->answers_section[i]));
                                                break;
                                            }
                                        }
                                    }

                                    for (int i = 0; i < store->m_arr[1]->nscount; i++) {
                                        ResourceRecord *rr1 = store->m_arr[1]->authoritative_section[i];

                                        for (int j = 0; j < msg->nscount; j++) {
                                            ResourceRecord *rr2 = msg->authoritative_section[j];

                                            if ((rr1->type == RRSIG && rr2->type == RRSIG) ||
                                                (rr1->type == DNSKEY && rr2->type == DNSKEY &&
                                                 (rr1->rdata[3] !=
                                                  SPHINCS_PLUS_SHA256_128S_ALG) &&
                                                 (rr2->rdata[3] !=
                                                  SPHINCS_PLUS_SHA256_128S_ALG))) {
                                                ResourceRecord *rr_combined;
                                                if (combine_rr(&rr_combined, rr1->name,
                                                               rr1->name_bytes,
                                                               rr1->name_byte_len, rr1->type,
                                                               rr1->clas, rr1->ttl,
                                                               rr1->rdsize, rr1->rdata,
                                                               rr2->rdsize, rr2->rdata) == 1)
                                                    continue;
                                                free(store->m_arr[1]->authoritative_section[i]);
                                                store->m_arr[1]->authoritative_section[i] = malloc(
                                                        sizeof(rr_combined));
                                                clone_rr(rr_combined,
                                                         &(store->m_arr[1]->authoritative_section[i]));
                                                break;
                                            }
                                        }
                                    }

                                    for (int i = 0; i < store->m_arr[1]->arcount; i++) {
                                        ResourceRecord *rr1 = store->m_arr[1]->additional_section[i];

                                        for (int j = 0; j < msg->arcount; j++) {
                                            ResourceRecord *rr2 = msg->additional_section[j];

                                            if ((rr1->type == RRSIG && rr2->type == RRSIG) ||
                                                (rr1->type == DNSKEY && rr2->type == DNSKEY &&
                                                 (rr1->rdata[3] !=
                                                  SPHINCS_PLUS_SHA256_128S_ALG) &&
                                                 (rr2->rdata[3] !=
                                                  SPHINCS_PLUS_SHA256_128S_ALG))) {
                                                ResourceRecord *rr_combined;
                                                if (combine_rr(&rr_combined, rr1->name,
                                                               rr1->name_bytes,
                                                               rr1->name_byte_len, rr1->type,
                                                               rr1->clas, rr1->ttl,
                                                               rr1->rdsize, rr1->rdata,
                                                               rr2->rdsize, rr2->rdata) == 1)
                                                    continue;
                                                free(store->m_arr[1]->additional_section[i]);
                                                store->m_arr[1]->additional_section[i] = malloc(
                                                        sizeof(rr_combined));
                                                clone_rr(rr_combined,
                                                         &(store->m_arr[1]->additional_section[i]));
                                                break;
                                            }
                                        }
                                    }

                                    printf("\nUpdated DNS Message: \n");
                                    if (debug)
                                        dnsmessage_to_string(store->m_arr[1]);
                                }

                                printf("\nDNS Message Complete!\n");
                                store->m_arr[1]->flags =
                                        store->m_arr[1]->flags & (65023 << 0);    // Mark as Un-Truncated
                                printf("\nSending Full DNS Message to bind9... \n");
                                send_dns_messsge(store->m_arr[1], iphdr, transport_header, is_tcp, 0);
                            }
                        }

                    }

                }
                return NF_DROP;
            } else {
                printf("Resolver : Accept DNS Response \n");
                uint16_t id = msg->identification;
                hashmap_remove(requester_state, &id, sizeof(uint16_t));
                return NF_ACCEPT;
            }

        } else if (daddr == our_addr && dport == 53) {
            printf("We should never have to process a response directed at port 53\n");
            fflush(stdout);
            ERROR();
        } else if (saddr == our_addr && sport == 53) {
            printf("* Send DNS Response *\n");
            if (debug)
                dnsmessage_to_string(msg);
            return NF_ACCEPT;
        } else {
            printf("Fell through...\n");
            ERROR();
        }
    }
    return NF_ACCEPT;
}

uint32_t process_tcp(struct nfq_q_handle *qh, uint32_t id, struct iphdr *ipv4hdr,
                     unsigned char *payload, size_t payloadLen) {
    struct tcphdr *tcphdr =
            (struct tcphdr *) ((char *) payload + sizeof(*ipv4hdr));
//    uint16_t src_port = ntohs(tcphdr->source);
//    uint16_t dst_port = ntohs(tcphdr->dest);

    return process_dns_message(qh, id, payload, payloadLen, ipv4hdr, tcphdr,
                               true, BYPASS);
}

uint32_t process_udp(struct nfq_q_handle *qh, uint32_t id, struct iphdr *ipv4hdr,
                     unsigned char *payload, size_t payloadLen) {
    struct udphdr *udphdr =
            (struct udphdr *) ((char *) payload + sizeof(*ipv4hdr));
//    uint16_t src_port = ntohs(udphdr->source);
//    uint16_t dst_port = ntohs(udphdr->dest);

    return process_dns_message(qh, id, payload, payloadLen, ipv4hdr, udphdr,
                               false, BYPASS);
}

uint32_t process_packet(struct nfq_q_handle *qh, struct nfq_data *data,
                        uint32_t **verdict) {
    // For the sake of testing getting this to work in docker containers
    // this is just going to print packet header info if it's a packet
    // addressed to this machine

    size_t payloadLen = 0;
    unsigned char *payload = NULL;
    struct iphdr *ipv4hdr;
//    struct icmphdr *icmphdr;
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    payloadLen = nfq_get_payload(data, &payload);
    ipv4hdr = (struct iphdr *) payload;
    ph = nfq_get_msg_packet_hdr(data);
    id = ntohl(ph->packet_id);

    uint32_t dst_ip = ipv4hdr->daddr;
    uint32_t src_ip = ipv4hdr->saddr;
    uint32_t res;
    /*
    Traffic with our address are sent to UDP and TCP processing function
    Other traffic with our IP is accepted
    Else if, UDP or ICMP --> DROP
    Else --> ACCEPT

    Question: WHY??? Changed it to accept..
    */
    if (dst_ip == our_addr || src_ip == our_addr) {
        if (ipv4hdr->protocol == IPPROTO_TCP) {
            res = process_tcp(qh, id, ipv4hdr, payload, payloadLen);
        } else if (ipv4hdr->protocol == IPPROTO_UDP) {
            res = process_udp(qh, id, ipv4hdr, payload, payloadLen);
        } else {
            res = NF_ACCEPT;
        }
    } else {
        res = NF_ACCEPT;
    }

    **verdict = res;
    // Again this 0xFFFF value...
    if (res == 0xFFFF) {
        return 0;
    }

    return id;

}

/*
Callback function for nfqueue
*/
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa,
              void *data) {
    uint32_t verdict;
    uint32_t *verdict_p = &verdict;
    uint32_t id = process_packet(qh, nfa, &verdict_p);

    // QUESTION: why don't we set a verdict in this case. What does 0xFFFF mean?
    if (*verdict_p == 0xFFFF) {
        return 0;
    }

    verdict = *verdict_p;
    if (verdict == NF_DROP) {
        //printf("dropping packet\n");
        //fflush(stdout);
    }

    if (verdict == NF_ACCEPT) {
        //printf("accepting packet\n");
        //fflush(stdout);
    }

    if (nfq_set_verdict(qh, id, verdict, 0, NULL) < 0) {
        printf("Verdict error\n");
        fflush(stdout);
        exit(-1);
    }

    return 0;
}

int get_addr(char *ipaddr) {
    inet_pton(AF_INET, ipaddr, &our_addr);
    return 0;
}

void free_key(void *key, size_t ksize, uintptr_t value, void *usr) {
    free(key);
}

void refresh_shared_map(shared_map **map) {
    if (map == NULL)
        return;
    shared_map *m = *map;
    if (m != NULL) {
        sem_wait(&(m->lock));
        hashmap_iterate(m->map, free_key, NULL);
        hashmap_free(m->map);
        m->map = hashmap_create();
        sem_post(&(m->lock));
    } else {
        init_shared_map(m);
    }

    *map = m;
}

void refresh_hashmap(hashmap **map) {
    if (map == NULL)
        return;
    hashmap *m = *map;
    if (m != NULL) {
        hashmap_iterate(m, free_key, NULL);
        hashmap_free(m);
    }

    m = hashmap_create();
    *map = m;
}

void refresh_state(void) {
    shared_map *rcp;
    shared_map *cip;
    rcp = &responder_cache;
    cip = &connection_info;
    refresh_shared_map(&rcp);
    refresh_shared_map(&cip);
    refresh_hashmap(&requester_state);
    refresh_hashmap(&responder_state);
}

/**
 * Main function contains CLI and main loop
 */
int main(int argc, char **argv) {
    signal(SIGINT, handle_signal);
    char *ipaddr;

    // max: ./daemon --is_resolver --bypass --debug --maxudp 1232 --algorithm FALCON512 --mode 2 = 10
    if (argc < 2 || argc > 11) {
        printf("\nWrong number of arguments: %d\n", argc);
        return -1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--is_resolver") == 0) {
            printf("Is a resolver\n");
            is_resolver = true;
        } else if (strcmp(argv[i], "--bypass") == 0) {
            printf("bypassing daemon\n");
            BYPASS = true;
        } else if (strcmp(argv[i], "--maxudp") == 0) {
            i++;
            MAXUDP = atoi(argv[i]);
            printf("Using maxudp: %u\n", MAXUDP);
        } else if (strcmp(argv[i], "--debug") == 0 ) {
            debug = true;
            printf("Enabling debugging...\n");
        } else if (strcmp(argv[i], "--algorithm") == 0) {
            i++;
            printf("Using algorithm: %s\n", argv[i]);
            if (strcmp(argv[i], "FALCON512") == 0)
                ALG = 0;
            else if (strcmp(argv[i], "DILITHIUM2") == 0)
                ALG = 1;
            else if (strcmp(argv[i], "SPHINCS+") == 0)
                ALG = 2;
            else if (strcmp(argv[i], "P256_FALCON512") == 0)
                ALG = 3;
            else if (strcmp(argv[i], "P256_DILITHIUM2") == 0)
                ALG = 4;
            else if (strcmp(argv[i], "MAYO1") == 0)
                ALG = 5;
            else {
                printf("Algorithm not supported!");
                exit(0);
            }
        } else if (strcmp(argv[i], "--mode") == 0) {
            i++;
            MODE = atoi(argv[i]);
            printf("Using mode: %u\n", MODE);
        } else {
            ipaddr = argv[i];
        }
    }

    printf("Starting daemon...\n");
    size_t buff_size = 0xffff;
    char buf[buff_size];
    int fd;
    /*get this machine's ip address from ioctl */
    if (get_addr(ipaddr) != 0)
        return -1;
    /*Create and initialize handle for netfilter_queue */
    struct nfq_handle *h = nfq_open();
    init_shared_map(&responder_cache);
    init_shared_map(&connection_info);
    requester_state = hashmap_create();
    responder_state = hashmap_create();

    if (!h) {
        printf("Failed getting h\n");
        return -1;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        printf("Failed to bind\n");
        return -1;
    }

    struct nfq_q_handle *qh;
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        printf("Failed to make queue\n");
        return -1;
    }

    if ((nfq_set_mode(qh, NFQNL_COPY_PACKET, buff_size)) == -1) {
        printf("Failed to tune queue\n");
        return -1;
    }

    fd = nfq_fd(h);
    printf("Listening...\n");
    fflush(stdout);

    /*
    Main loop:
    1. poll nfqueue fd (blocking)
    2. recv data
    3. call cb

    Notes:
    Poll is not needed since there is currently only 1 fd. 
    However, if we use multiple queues, poll becomes more efficient.

    Consider using mult-threading here.
     */
    int rv;
    struct pollfd ufd = { .fd = fd, .events = POLLIN };
    for (;;) {
        // blocking poll: change if non-blocking is required
        rv = poll(&ufd, 1, -1);    
        if (rv < 0) {
            printf("Failed to poll nfq\n");
            return -1;
        } else if (rv == 0) {
            // Timed out
        } else {
            rv = recv(fd, buf, sizeof(buf), 0);
            if (rv < 0) {
                printf("Failed to receive data\n");
                return -1;
            }
            nfq_handle_packet(h, buf, rv);
        }
    }
}
