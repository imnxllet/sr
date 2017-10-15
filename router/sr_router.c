/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    /* fill in code here */
    //int  sockfd;   /* socket to server */
    //char user[32]; /* user name */
    //char host[32]; /* host name */ 
    //char template[30]; /* template name if any */
    //unsigned short topo_id;
    //struct sockaddr_in sr_addr; /* address to server */
    //struct sr_if* if_list; /* list of interfaces */
    // struct sr_rt* routing_table; /* routing table */
    // struct sr_arpcache cache;   /* ARP cache */
    // pthread_attr_t attr;
    // FILE* logfile;

    /* Sanity check
       can only check length of ethernet packet for now.*/
    int minlength = sizeof(sr_ethernet_hdr_t);
    if (len < minlength || len > MTU){
      return;
    }

    /* Print ethenet packet header. */
    print_hdr_eth(packet);

    /* Create copy of packet */
    uint8_t *packet_copy =  (uint8_t *) malloc(sizeof(uint8_t) * len);
    memcpy(packet_copy, packet,len);

    char *iface = (char *) malloc(sizeof(char) * (strlen(interface) + 1));
    memcpy(iface, interface, strlen(interface) + 1);
    
    /* Save destination and source MAC address */
    /* Might not need this... */
    //uint8_t *dest_mac =  (uint8_t *) malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
    //memcpy(dest_mac, packet_copy->ether_dhost, ETHER_ADDR_LEN);
    //uint8_t *src_mac =  (uint8_t *) malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
    //memcpy(src_mac, packet_copy->ether_shost, ETHER_ADDR_LEN);


    /* Check packet type */
    uint16_t ethtype = ethertype(packet_copy);

    /* IP Packet */
    if (ethtype == ethertype_ip) {
        minlength += sizeof(sr_ip_hdr_t);
        if (length < minlength) {
          fprintf(stderr, "Failed to process IP packet, insufficient length\n");
          return;
        }

        //sr_ip_hdr *ip_packet = (sr_ip_hdr *) packet_copy + sizeof(sr_ethernet_hdr_t);
        sr_handleIPpacket(sr, packet_copy, len, iface); 



    /* ARP Packet*/
    }else if (ethtype == ethertype_arp) {
        minlength += sizeof(sr_arp_hdr_t);
        if (length < minlength){
            fprintf(stderr, "Failed to process ARP packet, insufficient length\n");
            return;
        }
        //sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t *) packet_copy + sizeof(sr_ethernet_hdr_t);
        sr_handleARPpacket(sr, packet_copy, len, iface) 

    

    /* Unrecognized type, drop it.*/
    }else{
        fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
        return;
    }
}/* end sr_handlepacket */

/* Handle IP Packet */
int sr_handleIPpacket(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface){

    /* Process the IP packet.. */
    sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*) packet_copy + sizeof(sr_ethernet_hdr_t);

    /* TO-DO: Essentially we need to check if this packet is ipv4*/

    /* See if this packet is for me or not. */
    int isforme = checkDestIsIface(ip_packet->ip_dst, sr);

    /* This packet is for one of the interfaces */
    if(isforme == 1){

        /* Check if it's ICMP or TCP/UDP */
        uint8_t ip_proto = ip_protocol(ip_packet);
        if (ip_proto == ip_protocol_icmp) { /* ICMP, send echo reply */
          printf("This packet is for me(Echo Req), send echo reply back...\n");
          return sendICMPmessage(sr, 0, 0, interface, packet);


        }else if(ip_proto == 0x0006 || ip_proto == 0x11){ /* TCP/UDP, Send ICMP Port Unreachable */
          printf("This packet is for me(TCP/UDP), send port unreachable back...\n");
          return sendICMPmessage(sr, 3, 3, interface, packet);
        }else{
          printf("This packet is for me, but type not recognized, drop it...\n");
          return -1;
        }

    /* Packet should be forwarded. */
    }else{

    }

}

/* Handle ARP Packet */
int sr_handleARPpacket(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface){

    /* Process the ARP packet.. */
    sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t *) packet_copy + sizeof(sr_ethernet_hdr_t);
}

/* Check an IP addr is one of the interfaces' IP */
int checkDestIsIface(uint32_t ip, struct sr_instance* sr){
    struct sr_if* if_walker = 0;
    if_walker = sr->if_list;

    while(if_walker)
    {
        if(ip == if_walker->ip){
            return 1;
        }
     
        if_walker = if_walker->next;
    }

    return 0;
}

int sendICMPmessage(struct sr_instance* sr, uint8_t icmp_type, 
  uint8_t icmp_code, char* iface, uint8_t * ori_packet){

  sr_ip_hdr_t *ori_ip_packet = (sr_ip_hdr_t*) ori_packet + sizeof(sr_ethernet_hdr_t);
  if(icmp_type == 0){/* Echo reply */

      /* Create Ethenet Packet */
      unsigned int len = (unsigned int) sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
      uint8_t *eth_packet = malloc(len);
      memcpy(eth_packet->dther_dhost, ori_packet->ether_shost, ETHER_ADDR_LEN);
      memcpy(eth_packet->ether_shost, ori_packet->dther_shost, ETHER_ADDR_LEN);
      eth_packet->ether_type = htons(ethertype_ip);

      /* Create IP packet */
      sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*) eth_packet + sizeof(sr_ethernet_hdr_t);
      ipHdr->ip_hl = 5;
      ip_packet->ip_v = 4;
      ip_packet->ip_tos = 0;
      ip_packet->ip_len = htons(icmpPacketLen - sizeof(sr_ethernet_hdr_t));
      ip_packet>ip_id = htons(1);
      ip_packet->ip_off = htons(IP_DF);
      ip_packet->ip_ttl = 64;
      ip_packet->ip_p = ip_protocol_icmp;

      /* Unknow for now?? lpm??*/
      ip_packet->ip_src = ori_ip_packet->ip_dst;
      
      
      ip_packet->ip_dst = ori_ip_packet->src;

      /* Create ICMP Type 0 header*/
      sr_icmp_hdr_t *icmp_packet = (sr_icmp_hdr_t *) ip_packet + sizeof(sr_ip_hdr_t);
      icmp_packet->icmp_type = icmp_type;
      icmp_packet->icmp_code = icmp_code;

      /* Doubt this ... */
      icmp_packet->icmp_sum = cksum(icmp_packet, sizeof(sr_icmp_hdr_t));

      ip_packet->ip_sum = cksum(icmp_packet, sizeof(sr_icmp_hdr_t));
      return sr_send_packet(sr,eth_packet, /*uint8_t*/ /*unsigned int*/ len, iface);





  }else{/* Type 3 reply */
      unsigned int len = (unsigned int) sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
      uint8_t * eth_packet = malloc(len);
      memcpy(eth_packet->dther_dhost, ori_packet->ether_shost, ETHER_ADDR_LEN);
      memcpy(eth_packet->ether_shost, ori_packet->dther_shost, ETHER_ADDR_LEN);
      eth_packet->ether_type = htons(ethertype_ip);

      /* Create IP packet */
      sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*) eth_packet + sizeof(sr_ethernet_hdr_t);
      ipHdr->ip_hl = 5;
      ip_packet->ip_v = 4;
      ip_packet->ip_tos = 0;
      ip_packet->ip_len = htons(icmpPacketLen - sizeof(sr_ethernet_hdr_t));
      ip_packet>ip_id = htons(1);
      ip_packet->ip_off = htons(IP_DF);
      ip_packet->ip_ttl = 64;
      ip_packet->ip_p = ip_protocol_icmp;

      /* Unknow for now?? lpm??*/
      ip_packet->ip_src = ori_ip_packet->ip_dst;
      
      
      ip_packet->ip_dst = ori_ip_packet->src;

      /* Create ICMP Type 0 header*/
      sr_icmp_t3_hdr_t *icmp_packet = (sr_icmp_t3_hdr_t*) ip_packet + sizeof(sr_ip_hdr_t);
      icmp_packet->icmp_type = icmp_type;
      icmp_packet->icmp_code = icmp_code;

      
      /* Take the original ip packet back */
      memcpy(icmp_packet->data, ori_ip_packet, ICMP_DATA_SIZE);
      /* Doubt this ... */
      icmp_packet->icmp_sum = cksum(icmp_packet, sizeof(sr_icmp_hdr_t));

      ip_packet->ip_sum = cksum(icmp_packet, sizeof(sr_icmp_hdr_t));
      return sr_send_packet(sr,eth_packet, /*uint8_t*/ /*unsigned int*/ len, iface);
  }

  

}