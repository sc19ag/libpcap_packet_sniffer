#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "sniffer.h"

#define MAXBYTESTOCAPTURE 65535
#define TCPDUMPTOMS 1000

void processPacket(u_char *userarg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    int *counter = (int *)userarg;

    printf("\nPacket Count: %d\n", ++(*counter));
    printf("Packet Size: %d\n", pkthdr->len);
    printf("Packet Payload:\n");

    for(int i = 0; i < pkthdr->len; i++) {
        if(isprint(packet[i])) {
            printf("%c ", packet[i]);
        } else {
            printf("? ");
        }

        if((i % 8 == 0 && i != 0) || i == pkthdr->len-1) {
            printf("\n");
        }
    }
    return;
}

void sniffToCli(int argc, char *argv[]) {
    pcap_t *devHandler = NULL;
    pcap_if_t **alldevsp; 
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask = 0;

    char *bpfFiltExp = NULL; // this will need to be passed to the function as parameter, once function works (should
                                // be user input). 

    //struct bpf_program *filtPointer;
    struct bpf_program filt; // see if passing filtPointer to pcap_compile and pcap_setfilter, rather than &filt, works if you 
                                // dynamically allocate memory to filtPointer right after declaring it i.e. before filtPointer is
                                // used in the functions.

    memset(errbuf, 0, PCAP_ERRBUF_SIZE);
    
    int pktCount = 5, counter; // This should be passed as a parameter, also, user input.
    printf("fine at 43\n");
    pcap_findalldevs(alldevsp, errbuf);
    printf("\nerrbuf after findalldevs: \n%s\n", errbuf);
    printf("fine at 45\n");
    dev = (**alldevsp).name;
    printf("fine at 47\n");

    devHandler = pcap_open_live(dev, MAXBYTESTOCAPTURE, 1, TCPDUMPTOMS, errbuf);
    printf("\nerrbuf after open_live: \n%s\n", errbuf);
    printf("fine at 50\n");

    pcap_compile(devHandler, &filt, bpfFiltExp, 1, mask);
    printf("fine at 53\n");
    pcap_setfilter(devHandler, &filt);
    printf("fine at 55\n");

    pcap_loop(devHandler, pktCount, processPacket, (u_char*)&counter);
    printf("fine at 58\n");

}

void sniffToFile(int argc, char *argv[], char *path) {
    printf("sniffToFile() called with filepath %s\n", path);
}