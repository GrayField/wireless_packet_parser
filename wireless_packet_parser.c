#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <signal.h>

#define	IEEE80211_ADDR_LEN	6
#define	IEEE80211_FC0_SUBTYPE_QOS	0x80
#define SIZE_OF_IEEE_802_11_QOS_FRAME 28
#define ETHTYPE_IP 0x08
#define PROTO_TCP 0x06

typedef struct radiotap_header{ // RadioTap is the standard for 802.11 reception/transmission/injection
    uint8_t it_rev; // Revision: Version of RadioTap
    uint8_t it_pad; // Padding: 0 - Aligns the fields onto natural word boundaries
    uint16_t it_len;
    uint32_t it_flag;
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

typedef struct ap_list {
    u_int8_t bssid[IEEE80211_ADDR_LEN];
    const u_char essid[128];
    int count;
    struct aplist* next;
} ap_list;

ap_list *head;

void initList() {
    head = (ap_list*)malloc(sizeof(ap_list));
    head->next =NULL;
}

ap_list* putList(ap_list* target, ap_list *temp) {
    ap_list *new;

    new = (ap_list*)malloc(sizeof(ap_list));
    
    memcpy(new, temp, sizeof(ap_list));

    new->next = target->next;
    target->next = new;

    return new;
}

int delList(ap_list* target) {
    ap_list* del;
    del = target->next;
    if( del == NULL) {
        return 0;
    }
    target->next = del->next;
    free(del);
    return 1;
}

ap_list* find_list(u_int8_t *bssid) {
    ap_list *temp;
    temp = head;

    do{
        if( !memcmp(temp->bssid, bssid, IEEE80211_ADDR_LEN) )
            break;
        temp = temp->next;
    }while(temp != NULL);

    return temp;
}

void parse_data_get(const u_char *data)
{
    puts("1***]parse_data_get");
    const u_char * start_ptr = NULL;
    const u_char * end_ptr = NULL;
    const u_char url[4096] = {0};
    const u_char host[256] = {0};
    const u_char cookie[4096] = {0};
    FILE *fp;

    fp = fopen("get.txt", "a+");
    if(fp == NULL) {
        printf("File Open Error!\n");
        fclose(fp);
        exit(1);
    }

    start_ptr = strstr(data, "GET");
    if(start_ptr != NULL) {
        end_ptr = strstr(start_ptr, "\r\n");
        memcpy(url, start_ptr, end_ptr-start_ptr);
        printf("%s\n", url);
        fprintf(fp, "%s\n", url);
    }

    start_ptr = strstr(data, "Host: ");
    if(start_ptr != NULL) {
        end_ptr = strstr(start_ptr, "\r\n");
        memcpy(host, start_ptr, end_ptr-start_ptr);
        printf("%s\n", host);
        fprintf(fp, "%s\n", host);
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
        fprintf(fp, "%s\n", cookie);
    }

    puts("");
    fprintf(fp, "\n");
    fclose(fp);

}

void parse_data_post(const u_char *data)
{
    puts("****]parse_data_post");
    const u_char * start_ptr = NULL;
    const u_char * end_ptr = NULL;
    const u_char url[4096] = {0};
    const u_char host[256] = {0};
    const u_char cookie[4096] = {0};
    const u_char param[4096] = {0};

    FILE *fp;
    fp = fopen("post.txt", "a+");
    if(fp == NULL) {
        printf("File Open Error\n");
        fclose(fp);
        exit(1);
    }

    start_ptr = strstr(data, "POST");
    if(start_ptr != NULL) {
        end_ptr = strstr(start_ptr, "\r\n");
        memcpy(url, start_ptr, end_ptr-start_ptr);
        printf("%s\n", url);
        fprintf(fp, "%s\n", url);
    }

    start_ptr = strstr(data, "Host: ");
    if(start_ptr != NULL) {
        end_ptr = strstr(start_ptr, "\r\n");
        memcpy(host, start_ptr, end_ptr-start_ptr);
        printf("%s\n", host);
        fprintf(fp, "%s\n", host);
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
        fprintf(fp, "%s\n", cookie);
    }

    // parse parameter
    start_ptr = strstr(data, "\r\n\r\n");
    start_ptr +=4;
    if(start_ptr != NULL) {
        end_ptr = strstr(start_ptr, "\r\n");
        if(end_ptr != NULL)
            memcpy(param, start_ptr, end_ptr-start_ptr);
        else {
            memcpy(param, start_ptr, strlen(start_ptr));
        }
        printf("%s\n", param);
        fprintf(fp, "%s\n", param);
    }

    puts("");
    fprintf(fp, "\n");
    fclose(fp);

    return;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    int size_80211hdr = 0, offset_ip = 0, offset_proto = 0, length=0;
    radiotap_header *rtaphdr;
    ieee80211_frame *wfhdr;
    ieee80211_qosframe *wqfhdr;
    llc_frame *llchdr;
    ip_frame *iphdr;
    tcp_hdr *tcphdr;
    int tag_len=0;
    const u_char essid[128] ={0};

    u_int8_t pkt[10240] = {0};

    ap_list *new;
    ap_list *temp;

    u_int16_t channel=0;

    new = (ap_list*)malloc(sizeof(ap_list));
    memset(new->essid, 0, 128);
    new->count=0;

    length = header->caplen;

    rtaphdr = (radiotap_header *) packet;
    if( rtaphdr->it_flag > 0xa0000000) {
        memcpy(&channel, packet+0x1a, 2);
    } else {
        memcpy(&channel, packet+0x12, 2);
    }

    // skip to next header
    packet += rtaphdr->it_len;
    length -= rtaphdr->it_len;

    wfhdr = (ieee80211_frame * ) packet;
    size_80211hdr = sizeof(ieee80211_frame);

    if( 0x88 == wfhdr->i_fc[0]) {

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
                    u_int32_t l_http = length - hdr_size - 4;
                    memcpy(pkt, p_http, l_http);

                    // find get
                    if( p_http[0] == 0x47 &&
                        p_http[1] == 0x45 &&
                        p_http[2] == 0x54)
                    {
                        // printf("%s\n", p_http);
                        parse_data_get(pkt);

                        if( (wqfhdr->i_fc[1] & 0x03) == 0x00) {
                            memcpy(new->bssid, wqfhdr->i_addr3, IEEE80211_ADDR_LEN);
                        } else if ( (wqfhdr->i_fc[1] & 0x03) == 0x01) {
                            memcpy(new->bssid, wqfhdr->i_addr1, IEEE80211_ADDR_LEN);
                        } else if ( (wqfhdr->i_fc[1] & 0x03) == 0x02) {
                            memcpy(new->bssid, wqfhdr->i_addr2, IEEE80211_ADDR_LEN);            
                        }

                        printf("++++]DEBUG: DS : %02x\n", wqfhdr->i_fc[1] & 0x03);
                        printf("++++]DEBUG: BSSID %02x:%02x:%02x:%02x:%02x:%02x\n", new->bssid[0], new->bssid[1], new->bssid[2], new->bssid[3], new->bssid[4], new->bssid[5]);                        
                        printf("++++]DEBUG: CHN : %d\n", channel);
                                                
                        temp = find_list(new->bssid);
                
                        if (temp==NULL) {
                            temp = putList(head, new);
                            printf("++++] HTTP(GET) ===> Put List Success\n");
                        } 
    
                        temp->count++;
                        
                        
                        printf("%02x:%02x:%02x:%02x:%02x:%02x => ", temp->bssid[0], temp->bssid[1], temp->bssid[2], temp->bssid[3], temp->bssid[4], temp->bssid[5]);                        
                        printf("%s, %d\n\n", temp->essid, temp->count);
                    }

                    //find post
                    if( p_http[0] == 0x50 &&
                        p_http[1] == 0x4F &&
                        p_http[2] == 0x53 &&
                        p_http[3] == 0x54)
                    {
                        // printf("%s\n", p_http);
                        parse_data_post(pkt);

                        if( (wqfhdr->i_fc[1] & 0x03) == 0x00) {
                            memcpy(new->bssid, wqfhdr->i_addr3, IEEE80211_ADDR_LEN);
                        } else if ( (wqfhdr->i_fc[1] & 0x03) == 0x01) {
                            memcpy(new->bssid, wqfhdr->i_addr1, IEEE80211_ADDR_LEN);
                        } else if ( (wqfhdr->i_fc[1] & 0x03) == 0x02) {
                            memcpy(new->bssid, wqfhdr->i_addr2, IEEE80211_ADDR_LEN);            
                        }

                        printf("++++]DEBUG: DS %02x\n", wqfhdr->i_fc[1] & 0x03);
                        printf("++++]DEBUG: BSSID %02x:%02x:%02x:%02x:%02x:%02x\n", new->bssid[0], new->bssid[1], new->bssid[2], new->bssid[3], new->bssid[4], new->bssid[5]);                        
                        printf("++++]DEBUG: CHN : %d\n", channel);
                        
                                                
                        temp = find_list(new->bssid);
                
                        if (temp==NULL) {
                            temp = putList(head, new);
                            printf("++++] HTTP(POST) ===> Put List Success\n");
                        } 
    
                        temp->count++;

                        printf("%02x:%02x:%02x:%02x:%02x:%02x => ", temp->bssid[0], temp->bssid[1], temp->bssid[2], temp->bssid[3], temp->bssid[4], temp->bssid[5]);                        
                        printf("%s, %d\n\n", temp->essid, temp->count);
                    }
                }
            }
        }
    } 
    else if ( 0x80 == wfhdr->i_fc[0])
    {
        // find bssid and essid
        size_80211hdr = sizeof(ieee80211_frame);

        packet += size_80211hdr;
        length -= size_80211hdr;

        // skip wireless lan fixed param
        packet +=12;
        tag_len = (int)( *(packet+1) );
        memcpy(essid, packet+2, tag_len);
        // printf("%02x:%02x:%02x:%02x:%02x:%02x", wfhdr->i_addr2[0], wfhdr->i_addr2[1], wfhdr->i_addr2[2], wfhdr->i_addr2[3], wfhdr->i_addr2[4], wfhdr->i_addr2[5]);
        // printf(" == %s\n", essid);
        if( (wfhdr->i_fc[1] & 0x03) == 0x00) {
            memcpy(new->bssid, wfhdr->i_addr3, IEEE80211_ADDR_LEN);
        } else if ( (wfhdr->i_fc[1] & 0x03) == 0x01) {
            memcpy(new->bssid, wfhdr->i_addr1, IEEE80211_ADDR_LEN);
        } else if ( (wfhdr->i_fc[1] & 0x03) == 0x02) {
            memcpy(new->bssid, wfhdr->i_addr2, IEEE80211_ADDR_LEN);            
        }

        // printf("%x\n", wqfhdr->i_fc[1] & 0x03);
        // printf("%02x:%02x:%02x:%02x:%02x:%02x\n", new->bssid[0], new->bssid[1], new->bssid[2], new->bssid[3], new->bssid[4], new->bssid[5]);                        

        memcpy(new->essid, essid, strlen(essid));

        temp = find_list(new->bssid);

        if (temp==NULL) {
            temp = putList(head, new);
            printf("++++] BEACON ===> Put List Success [+++++\n");
            printf("++++] BEACON %02x:%02x:%02x:%02x:%02x:%02x", temp->bssid[0], temp->bssid[1], temp->bssid[2], temp->bssid[3], temp->bssid[4], temp->bssid[5]);
            printf(" ==> %s\n", temp->essid);
            printf("++++] BEACON CHN %d\n", channel);

        } else if ( !strcmp(temp->essid, "") ){
            memcpy(temp->essid, essid, strlen(essid));
        }

        
    }

    free(new);
	return;
}

void(*old_fun)(int);

// save data when control+c press
void sigint_handler(int signo)
{
    FILE *fp;
    fp = fopen("ap_result.txt", "a+");
    ap_list *temp, *temp2;
    temp2 = head->next;

    while(temp2 != NULL) {
        fprintf(fp, "BSSID] %02x:%02x:%02x:%02x:%02x:%02x\n", temp2->bssid[0], temp2->bssid[1], temp2->bssid[2], temp2->bssid[3], temp2->bssid[4], temp2->bssid[5]);
        fprintf(fp, "ESSID] %s\n", temp2->essid);
        fprintf(fp, "COUNT] %d\n", temp2->count);

        // move to next node
        temp = temp2;
        temp2 = temp2->next;
        free(temp);
    }

    fclose(fp);
    exit(1);
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

        initList();

        old_fun = signal(SIGINT, sigint_handler);

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
set:
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

        printf("****]Start\n");

        result = pcap_loop(handle, 0, packet_handler, NULL);
        
        //Can't restore interface wlan0 wireless mode (SIOCSIWMODE failed: Device or resource busy).
        // Please adjust manually.
        printf("%d: %s\n", result, pcap_geterr(handle));

        if(result==-1)
            goto set;

        pcap_freealldevs(alldevs);
            
        pcap_close(handle);
        

        return 0;

}
