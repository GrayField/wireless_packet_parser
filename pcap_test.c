#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

#define	IEEE80211_ADDR_LEN	6
#define	IEEE80211_FC0_SUBTYPE_QOS	0x80
#define SIZE_OF_IEEE_802_11_QOS_FRAME 28
#define ETHTYPE_IP 0x08
#define PROTO_TCP 0x06

typedef struct radiotap_header{ // RadioTap is the standard for 802.11 reception/transmission/injection
    uint8_t it_rev; // Revision: Version of RadioTap
    uint8_t it_pad; // Padding: 0 - Aligns the fields onto natural word boundaries
    uint16_t it_len;
}radiotap_header;

typedef struct ieee80211_frame {
	u_int8_t	i_fc[2];
	u_int8_t	i_dur[2];
	u_int8_t	i_addr1[IEEE80211_ADDR_LEN];
	u_int8_t	i_addr2[IEEE80211_ADDR_LEN];
	u_int8_t	i_addr3[IEEE80211_ADDR_LEN];
	u_int8_t	i_seq[2];
} ieee80211_frame;

typedef struct ieee80211_qosframe {
	u_int8_t	i_fc[2];
	u_int8_t	i_dur[2];
	u_int8_t	i_addr1[IEEE80211_ADDR_LEN];
	u_int8_t	i_addr2[IEEE80211_ADDR_LEN];
	u_int8_t	i_addr3[IEEE80211_ADDR_LEN];
	u_int8_t	i_seq[2];
	u_int8_t	i_qos[2];
} ieee80211_qosframe;

typedef struct llc_frame {
    u_int8_t    i_dsap;
    u_int8_t    i_ssap;
    u_int8_t    i_ctrl;
    u_int8_t    i_org[3];
    u_int16_t   i_ethtype;
} llc_frame;

typedef struct ip_frame {
    u_int8_t    ver;
    u_int8_t    tos;
    u_int16_t   tot_len;
    u_int16_t   id;
    u_int16_t   frag_off;
    u_int8_t    ttl;
    u_int8_t    protocol;
    u_int16_t   check;
    u_int32_t   saddr;
    u_int32_t   daddr;
} ip_frame;

typedef struct tcp_hdr {
    u_int16_t sport;
    u_int16_t dport;
    u_int32_t seqnu;
    u_int32_t ack_seq;
    //u_int16_t len_flags;
    u_int16_t res1:4,
              doff:4,
              fin:1,
              syn:1,
              rst:1,
              psh:1,
              ack:1,
              urg:1,
              ece:1,
              cwr:1;
    u_int16_t window;
    u_int16_t checksum;
    u_int16_t urg_ptr;
} tcp_hdr;

void parse_data_get(const u_char *data)
{
    const u_char * start_ptr = NULL;
    const u_char * end_ptr = NULL;
    const u_char get_url[256] = {0};
    const u_char host[256] = {0};
    const u_char cookie[512] = {0};

    start_ptr = strstr(data, "GET");
    if(start_ptr != NULL) {
        end_ptr = strstr(start_ptr, "\r\n");
        memcpy(get_url, start_ptr, end_ptr-start_ptr);
        printf("%s\n", get_url);
    }

    start_ptr = strstr(data, "Host: ");
    if(start_ptr != NULL) {
        end_ptr = strstr(start_ptr, "\r\n");
        memcpy(host, start_ptr, end_ptr-start_ptr);
        printf("%s\n", host);
    }

    start_ptr = strstr(data, "Cookie: ");
    if(start_ptr != NULL) {
        end_ptr = strstr(start_ptr, "\r\n");
        if(end_ptr != NULL)
            memcpy(cookie, start_ptr, end_ptr-start_ptr);
        else {
            memcpy(cookie, start_ptr, strlen(start_ptr));
        }
        printf("%s\n", cookie);
    }
    puts("");

}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    int size_80211hdr = 0, offset_ip = 0, offset_proto = 0, length=0;
    radiotap_header *rtaphdr;
    ieee80211_frame *wfhdr;
    ieee80211_qosframe *wqfhdr;
    llc_frame *llchdr;
    ip_frame *iphdr;
    tcp_hdr *tcphdr;

    u_int8_t pkt[2048] = {0};

    length = header->caplen;

	rtaphdr = (radiotap_header *) packet;

    // skip to next header
    packet += rtaphdr->it_len;
    length -= rtaphdr->it_len;

    wfhdr = (ieee80211_frame * ) packet;
    size_80211hdr = sizeof(ieee80211_frame);

    if( 0x88 != wfhdr->i_fc[0]) {
        return;
    }

    wqfhdr = (ieee80211_qosframe *) packet;
    size_80211hdr = sizeof(ieee80211_qosframe);

    // printf("FC: %x\n", wfhdr->i_fc[0]);
    // printf("Flag: %x\n", wqfhdr->i_fc[1]);
    // printf("Duration: %d microsec\n", ((int)wqfhdr->i_dur[0])*128 + (int)wqfhdr->i_dur[1]);
    // printf("%2x:%2x:%2x:%2x:%2x:%2x\n", wqfhdr->i_addr1[0], wqfhdr->i_addr1[1], wqfhdr->i_addr1[2], wqfhdr->i_addr1[3], wqfhdr->i_addr1[4],wqfhdr->i_addr1[5],wqfhdr->i_addr1[6]);  
    
    // skip to next header
    packet += size_80211hdr;
    length -= size_80211hdr;

    llchdr = (llc_frame*) packet;

    // skip to next header
    packet += sizeof(struct llc_frame);

    // i_ethtype is ip
    if((short)ETHTYPE_IP == llchdr->i_ethtype)
    {
        offset_ip = size_80211hdr + sizeof(llc_frame);
        offset_proto = offset_ip + sizeof(ip_frame);

        iphdr = (ip_frame*)packet;

        // skip to next header
        packet += sizeof(ip_frame);
        length -= sizeof(ip_frame);

        // protocol is tcp
        if((short)PROTO_TCP == iphdr->protocol)
        {
            tcphdr = (tcp_hdr*)packet;

            // http
            if (80 == ntohs(tcphdr->dport))
            {
                // printf("HTTP\n");
                u_int32_t hdr_size = tcphdr->doff*4;
                u_int8_t *p_http = packet + hdr_size;
                u_int32_t l_http = length - hdr_size-6;
                memcpy(pkt, p_http, l_http);

                // find get
                if( p_http[0] == 0x47 &&
                    p_http[1] == 0x45 &&
                    p_http[2] == 0x54)
                {
                    // printf("%s\n", p_http);
                    parse_data_get(pkt);
                }

                //find post
                if( p_http[0] == 0x50 &&
                    p_http[1] == 0x4F &&
                    p_http[2] == 0x53 &&
                    p_http[4] == 0x54)
                {
                    // printf("%s\n", p_http);
                    // parse_data(pkt);
                }
            }
        }
    }

	return;
}


int main(int argc, char **argv)

{
        char *dev;
        char *net;
        char *mask;
        int result;

        int ret = 0, i = 0, inum = 0, check=0;
        pcap_if_t *alldevs;
        pcap_if_t *d;
        pcap_t *handle;

        char errbuf[PCAP_ERRBUF_SIZE];
        bpf_u_int32 netp;
        bpf_u_int32 maskp;
        struct in_addr addr;


        ret = pcap_findalldevs(&alldevs, errbuf);
        if (ret == -1)
        {
            printf("pcap_findalldevs: %s\n", errbuf);
            exit(1);
        }

        for(d = alldevs; d; d = d->next)
        {
            printf("%d: %s: ", ++i, d->name);
            if (d->description)
                printf("%d description: %s\n", i, d->description);
            else
                printf("No description available\n");
        }


        printf("Enter interface number (1-%d): ", i);
        scanf("%d", &inum);

        if(inum < 1 || inum > i)
        {
            printf("Please enter number between 1-%d", i);
            exit(1);
        }

        for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

        printf("DEV: %s\n", d->name);

        handle = pcap_create(d->name, errbuf);

        // check monitor mode could be set
        check = pcap_can_set_rfmon(handle);
        if(check != 1)
        {
    
            switch(check)
            {
                case PCAP_ERROR_NO_SUCH_DEVICE:
                    printf("Can not find device\n");
                    exit(1);
                    break;
                case PCAP_ERROR_PERM_DENIED:
                    printf("The process doesn't have permission to check\n");
                    exit(1);
                    break;
                case PCAP_ERROR_ACTIVATED:
                    printf("The capture handle has already been activated\n");
                    exit(1);
                    break;
                case PCAP_ERROR:
                    printf("Unkown error\n");
                    exit(1);
                    break;
                case 0:
                    printf("Monitor mode could not be set\n");
                    exit(1);
                default:
                    break;
            }
        } 
        else
        {
            if(check==1)
            {
                // printf("Monitor mode could be set\n");
                if(pcap_set_rfmon(handle, 1))
                {
                    printf("Can not set monitor mode\n");
                    exit(1);
                }
                
                if(pcap_set_promisc(handle, 1))
                {
                    printf("Can not set promiscuous mode\n");
                    exit(1);
                }

                if(pcap_set_snaplen(handle, 2048))
                {
                    printf("Set snap length error\n");
                    exit(1);
                }

                if(pcap_set_timeout(handle, 1000))
                {
                    printf("Set timeout error\n");
                    exit(1);
                }

                pcap_activate(handle);
                //handle is ready


            }
        }

        printf("Start\n");

        pcap_freealldevs(alldevs);

        result = pcap_loop(handle, 0, packet_handler, NULL);
        
        printf("%d: Pcap Loop is terminated\n", result);
        pcap_close(handle);
        

        return 0;

}