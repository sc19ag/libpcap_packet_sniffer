#include <stdio.h>
#include <ctype.h>
#include <pcap/pcap.h>
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

    struct bpf_program *filtPointer;
    
    int pktCount = 5, counter; // This should be passed as a parameter, also, user input.

    pcap_findalldevs(alldevsp, errbuf);
    dev = (**alldevsp).name;

    devHandler = pcap_open_live(dev, MAXBYTESTOCAPTURE, 1, TCPDUMPTOMS, errbuf);

    pcap_compile(devHandler, filtPointer, bpfFiltExp, 1, mask);
    pcap_setfilter(devHandler, filtPointer);

    pcap_loop(devHandler, pktCount, processPacket, (u_char*)&counter);

}

void sniffToFile(int argc, char *argv[], char *path) {
    printf("sniffToFile() called with filepath %s\n", path);
}