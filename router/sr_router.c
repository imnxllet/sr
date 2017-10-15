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
#include <stdlib.h>
#include <string.h>

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
  

    /* Sanity check
       can only check length of ethernet packet for now.*/
    int minlength = sizeof(sr_ethernet_hdr_t);
    if (len < minlength || len > MTU){
      return;
    }

    /* Print ethenet packet header. */
    print_hdrs(packet, len);

    /* Create copy of packet */
    uint8_t *packet_copy =  (uint8_t *) malloc(sizeof(uint8_t) * len);
    memcpy(packet_copy, packet,len);

    char *iface = (char *) malloc(sizeof(char) * (strlen(interface) + 1));
    memcpy(iface, interface, strlen(interface) + 1);
    
    /* Save destination and source MAC address */
    /* Might not need this... */
    /*uint8_t *dest_mac =  (uint8_t *) malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);*/
    /*memcpy(dest_mac, packet_copy->ether_dhost, ETHER_ADDR_LEN);*/
    /*uint8_t *src_mac =  (uint8_t *) malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);*/
    /*memcpy(src_mac, packet_copy->ether_shost, ETHER_ADDR_LEN);*/


    /* Check packet type */
    uint16_t ethtype = ethertype(packet_copy);

    /* IP Packet */
    if (ethtype == ethertype_ip) {
        minlength += sizeof(sr_ip_hdr_t);
        if (len < minlength) {
          fprintf(stderr, "Failed to process IP packet, insufficient length\n");
          return;
        }

        /*sr_ip_hdr *ip_packet = (sr_ip_hdr *) packet_copy + sizeof(sr_ethernet_hdr_t);*/
        printf("This is a IP packet...\n");
        int handle_signal = sr_handleIPpacket(sr, packet_copy, len, iface); 
        return;



    /* ARP Packet*/
    }else if (ethtype == ethertype_arp) {
        minlength += sizeof(sr_arp_hdr_t);
        if (len < minlength){
            fprintf(stderr, "Failed to process ARP packet, insufficient length\n");
            return;
        }
        /*sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t *) packet_copy + sizeof(sr_ethernet_hdr_t);*/
        printf("This is a ARP packet...\n");
        int handle_signal = sr_handleARPpacket(sr, packet_copy, len, iface);
        return; 

    

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
    print_hdr_ip((uint8_t *) (packet + sizeof(sr_ethernet_hdr_t)));
    sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t));

    /* TO-DO: Essentially we need to check if this packet is ipv4*/

    /* See if this packet is for me or not. */
    struct sr_if *target_if = (struct sr_if*) checkDestIsIface(ip_packet->ip_dst, sr);

    /* This packet is for one of the interfaces */
    if(target_if != 0){
        printf("This is for me...\n");
        /* Check if it's ICMP or TCP/UDP */
        uint8_t ip_proto = ip_protocol((uint8_t *) ip_packet);
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

      return 0;

    }
    return 0;
}

/* Handle ARP Packet, Find MAC addr for a new IP addr*/
int sr_handleARPpacket(struct sr_instance* sr,
        uint8_t * packet,
        unsigned int len,
        char* interface){

    /* Process the ARP packet.. */
    sr_arp_hdr_t *arp_packet = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /* Get the dest ip and see which interface it is.. */
    struct sr_if *target_if = (struct sr_if*) checkDestIsIface(arp_packet->ar_tip, sr);

    /* Error check */
    if(target_if == 0){
      fprintf(stderr, "Some weird error.\n");
      return -1;
    }
    /* Check if this is reply or request */
    if(arp_packet->ar_op == htons(arp_op_request)){/* Req. Construct reply with MAC addr*/
        printf("This is an ARP request, preparing ARP reply...\n"); 
        len = (unsigned int) sizeof(sr_ethernet_hdr_t) +  sizeof(sr_arp_hdr_t);
  
        uint8_t *eth_packet = malloc(len);
        memcpy(((sr_ethernet_hdr_t *)eth_packet)->ether_dhost, ((sr_ethernet_hdr_t *)packet)->ether_shost, ETHER_ADDR_LEN);
        /* Source MAC is current Interface*/
        memcpy(((sr_ethernet_hdr_t *)eth_packet)->ether_shost, target_if->addr, ETHER_ADDR_LEN);
        ((sr_ethernet_hdr_t *)eth_packet)->ether_type = htons(ethertype_arp);

        /* Create IP packet */
        sr_arp_hdr_t *arp_reply = (sr_arp_hdr_t*) (eth_packet + sizeof(sr_ethernet_hdr_t));

        arp_reply->ar_hrd = htons(arp_hrd_ethernet);             /* format of hardware address   */
        arp_reply->ar_pro = htons(0x0800);             /* format of protocol address   */
        arp_reply->ar_hln = 6;             /* length of hardware address   */
        arp_reply->ar_pln = 4;             /* length of protocol address   */
        arp_reply->ar_op = htons(arp_op_reply);              /* ARP opcode (command)         */
        memcpy(arp_reply->ar_sha, target_if->addr,ETHER_ADDR_LEN);/* sender hardware address      */
        arp_reply->ar_sip = target_if->ip;             /* sender IP address            */
        memcpy(arp_reply->ar_tha, arp_packet->ar_sha,ETHER_ADDR_LEN);/* target hardware address      */
        arp_reply->ar_tip = arp_packet->ar_sip;

        printf("Sending back ARP reply...Detail below:\n");  
        print_hdrs(eth_packet, len);         
        
        return sr_send_packet(sr,eth_packet, /*uint8_t*/ /*unsigned int*/ len, interface);

    }else if(arp_packet->ar_op == htons(arp_op_reply)){
      printf("This is an ARP reply...\n"); 
      return 0;

    }else{
      fprintf(stderr, "This ARP packet is of unknown type.\n");
      return -1;
    }


    return 0;
}

/* Check an IP addr is one of the interfaces' IP */
struct sr_if* checkDestIsIface(uint32_t ip, struct sr_instance* sr){

    printf("Checking if this is for me...\n");
    printf("Current IP: ");
    print_addr_ip_int(ip);
    struct sr_if* if_walker = 0;
    if_walker = sr->if_list;

    while(if_walker)
    {   
      printf("\nIface Ip:");
        print_addr_ip_int(if_walker->ip);
        if(ip == if_walker->ip){
            return if_walker;
        }
     
        if_walker = if_walker->next;
    }

    return 0;
}

int sendICMPmessage(struct sr_instance* sr, uint8_t icmp_type, 
  uint8_t icmp_code, char* iface, uint8_t * ori_packet){

  printf("Creating ICMP message..\n");

  sr_ip_hdr_t *ori_ip_packet = (sr_ip_hdr_t*) (ori_packet + sizeof(sr_ethernet_hdr_t));
  unsigned int len = 0;
  if(icmp_type == 0){/* Echo reply */
      /* Create Ethenet Packet */
      printf("Creating echo reply..\n");
      len = (unsigned int) sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
  }else{/* Type 3 reply */
      printf("Creating unreachable reply..\n");
      len = (unsigned int) sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
  }
  uint8_t *eth_packet = malloc(len);
  memcpy(((sr_ethernet_hdr_t *)eth_packet)->ether_dhost, ((sr_ethernet_hdr_t *)ori_packet)->ether_shost, ETHER_ADDR_LEN);
  memcpy(((sr_ethernet_hdr_t *)eth_packet)->ether_shost, ((sr_ethernet_hdr_t *)ori_packet)->ether_dhost, ETHER_ADDR_LEN);
  ((sr_ethernet_hdr_t *)eth_packet)->ether_type = htons(ethertype_ip);

  /* Create IP packet */
  sr_ip_hdr_t *ip_packet = (sr_ip_hdr_t*) (eth_packet + sizeof(sr_ethernet_hdr_t));
  ip_packet->ip_hl = 5;
  ip_packet->ip_v = 4;
  ip_packet->ip_tos = 0;
  ip_packet->ip_len = htons(len - sizeof(sr_ethernet_hdr_t));
  ip_packet->ip_id = htons(1);
  ip_packet->ip_off = htons(IP_DF);
  ip_packet->ip_ttl = 64;
  ip_packet->ip_p = ip_protocol_icmp;

  /* Unknow for now?? lpm??*/
  ip_packet->ip_src = ori_ip_packet->ip_dst;
  
  
  ip_packet->ip_dst = ori_ip_packet->ip_src;

  /* Create ICMP Type 0 header*/
  


  
  if(icmp_type == 0){
      /* Doubt this ... */
      sr_icmp_hdr_t *icmp_packet = (sr_icmp_hdr_t *) (ip_packet + sizeof(sr_ip_hdr_t));
      icmp_packet->icmp_type = icmp_type;
      icmp_packet->icmp_code = icmp_code;
      icmp_packet->icmp_sum = cksum(icmp_packet, sizeof(sr_icmp_hdr_t));
  }else{
      /* Take the original ip packet back */
      sr_icmp_t3_hdr_t *icmp_packet = (sr_icmp_t3_hdr_t *) (ip_packet + sizeof(sr_ip_hdr_t));
      memcpy(icmp_packet->data, ori_ip_packet, ICMP_DATA_SIZE);
      icmp_packet->icmp_sum = cksum(icmp_packet, sizeof(sr_icmp_t3_hdr_t));
      icmp_packet->icmp_type = icmp_type;
      icmp_packet->icmp_code = icmp_code;
  }

  ip_packet->ip_sum = cksum(ip_packet, sizeof(sr_ip_hdr_t));
  printf("Eth pakcet prepared, ready to send...\n");
  print_hdrs(eth_packet, len);
  printf("--------------------------\n");
  return sr_send_packet(sr,eth_packet, /*uint8_t*/ /*unsigned int*/ len, iface);

}