#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

/* Callback function invoked by libpcap for every incoming packet */
// void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
// {
//     struct ether_header *eth_header;
//     eth_header = (struct ether_header *) pkt_data;

//     if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
//         printf("IP\n");
//     } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
//         printf("ARP\n");
//     } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
//         printf("Reverse ARP\n");
//     }    
// }

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	// This struct is the RadioTap header: https://radiotap.org
	struct radiotap_header{ // RadioTap is the standard for 802.11 reception/transmission/injection
		uint8_t it_rev; // Revision: Version of RadioTap
		uint8_t it_pad; // Padding: 0 - Aligns the fields onto natural word boundaries
		uint16_t it_len;// Length: 26 - entire length of RadioTap header
	};
	// These are placeholders for offset values:
	const u_char *bssid; // a place to put our BSSID \ these are bytes
	const u_char *essid; // a place to put our ESSID / from the packet
	const u_char *essidLen;
	const u_char *channel; // the frequency (in Mhz) of the AP Radio
	const u_char *rssi; // received signal strength

	int offset = 0;
	struct radiotap_header *rtaphdr;
	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len; // 26 bytes on my machine
	//if(packet[offset]==0x80){ // 0x80 is 128 in dec. It is a Beacon MGMT frame // REMOVED for BPF syntax
	bssid = packet + 42; // store the BSSID/AP MAC addr, 36 byte offset is transmitter address
	essid = packet + 64; // store the ESSID/Router name too
	essidLen = packet + 63; // store the ESSID length // this can be used to avoid looping bytes until >0x1 as below
	rssi = packet + 22; // this is hex and this value is subtracted from 256 to get -X dbm.
	signed int rssiDbm = rssi[0] - 256;
	channel = packet + 18; // channel in little endian format (2 bytes)
	int channelFreq = channel[1] * 256 + channel[0]; // a little bit of math, remember little endian
	// 87 byte offset contains the "channel number" as per 802.11, e.g. 2412 = "channel 11"
	char *ssid = malloc(63); // 63 byte limit
	unsigned int i = 0; // used in loop below:
	while(essid[i] > 0x1){ // uncomment these to see each byte individually:
		//printf ("hex byte: %x\n",essid[i]); // view byte
		//printf ("hex char: %c\n",essid[i]); // view ASCII
		ssid[i] = essid[i]; // store the ESSID bytes in *ssid
		i++; // POSTFIX
	}
	ssid[i] = '\0'; // terminate the string
	fprintf(stdout,"RSSI: %d dBm\n",rssiDbm);
	fprintf(stdout,"AP Frequency: %iMhz\n",channelFreq);
	fprintf(stdout,"ESSID length: %i bytes.\n",essidLen[0]);
	fprintf(stdout,"ESSID string: %s\n", ssid); // print the stored ESSID bytes
    fprintf(stdout,"BSSID string: %02X:%02X:%02X:%02X:%02X:%02X\n",bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]);
    fprintf(stdout,"All packet  : %s\n", packet);
	//} // REMOVED for BPF syntax
	
	// Let's write the beacon to a file:
	pcap_dumper_t *outputFile;
	pcap_t *fileHandle;
	char *outputFileName = "output.cap";
	fileHandle = pcap_open_dead(DLT_IEEE802_11_RADIO, BUFSIZ);
	outputFile = pcap_dump_open(fileHandle,outputFileName);
	pcap_dump((u_char *) outputFile,header, packet);
    pcap_close(fileHandle);
    

	return;
}


int main(int argc, char **argv)

{
        char *dev;
        char *net;
        char *mask;

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
                printf("Monitor mode could be set\n");
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

        pcap_loop(handle, 0, packet_handler, NULL);

        pcap_close(handle);
        pcap_freealldevs(alldevs);

        return 0;

}