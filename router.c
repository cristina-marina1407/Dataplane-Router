#include "queue.h"
#include "lib.h"
#include <string.h>
#include <stdbool.h>
#include "trie.h"

#define MAX_ENTRIES 100000
#define IPV4 0x0800
#define ARP  0x0806
#define MAC_ADDR_SIZE  6
#define DESTINATION_UNREACHABLE_TYPE 3
#define DESTINATION_UNREACHABLE_CODE 0
#define TIME_EXCEEDED_TYPE 11
#define TIME_EXCEEDED_CODE 0
#define ECHO_REQUEST_TYPE 8
#define ECHO_REQUEST_CODE 0
#define ECHO_REPLY_TYPE 0
#define ECHO_REPLY_CODE 0
#define DEFAULT_TTL 64

/* Declare global variables */

/* Routing table */
struct route_table_entry *rtable;

/* Number of entries in the routing table */
int rtable_length = 0;

/* ARP table */
struct arp_table_entry *arp_table;

/* Number of entries in the ARP table */
int arp_table_length = 0;

/* Trie root for the routing table */
trie_node_t *trie_root;

/* Function to check if the MAC address is broadcast address */
int is_broadcast_mac(uint8_t *mac) {
	for (int i = 0; i < 6; i++) {
		if (mac[i] != 0xFF) {
			return 0;
		}
	}
	return 1;
}

/* Function to update L2 addresses (MAC addresses) in Ethernet header */
void update_next_hop_addresses(struct ether_hdr *ether_header,
							struct route_table_entry *route, char *buf) {
	struct ether_hdr *new_ether_header = (struct ether_hdr *)buf;

	get_interface_mac(route->interface, ether_header->ethr_shost);

	uint8_t *next_hop_mac = NULL;
	
    /* Search the ARP table for the next hop MAC address */
	for (int i = 0; i < arp_table_length; i++) {
		if (arp_table[i].ip == route->next_hop) {
			next_hop_mac = arp_table[i].mac;
			break;
		}
	}

	 if (next_hop_mac == NULL) {
		return;
	}

	memcpy(new_ether_header->ethr_dhost, next_hop_mac, MAC_ADDR_SIZE);
}

/* Function to build a new ethernet header for the icmp responses */
void build_ethernet_header(char *packet, uint8_t *src_mac, uint8_t *dst_mac,
						   uint16_t eth_type) {
    struct ether_hdr *eth_hdr = (struct ether_hdr *)packet;

	/* Interchange the source and destination from the ethernet header */
    memcpy(eth_hdr->ethr_shost, src_mac, MAC_ADDR_SIZE);
    memcpy(eth_hdr->ethr_dhost, dst_mac, MAC_ADDR_SIZE);

	/* Set the type */
    eth_hdr->ethr_type = htons(eth_type);
}

/* Function to build a new ip header for the icmp responses */
void build_ip_header(struct ip_hdr *ip_hdr, uint32_t src_ip, uint32_t dst_ip,
					 uint16_t total_len, uint8_t ttl, uint8_t protocol) {
    ip_hdr->ver = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = htons(total_len);
    ip_hdr->id = 0;
    ip_hdr->frag = 0;

	/* Set the default ttl */ 
    ip_hdr->ttl = ttl;

    ip_hdr->proto = protocol;
    ip_hdr->source_addr = src_ip;
    ip_hdr->dest_addr = dst_ip;
    ip_hdr->checksum = 0;

	/* Recalculate the checksum after chaging the ttl */
    ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));
}

/* Function to handle the ICMP packet */
void analyze_icmp_packet(char *buf, size_t len, size_t interface,
						 uint8_t type, uint8_t code) {
	struct ether_hdr *ether_header = (struct ether_hdr *)buf;
	struct ip_hdr *ip_header = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	struct icmp_hdr *icmp_header = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr)
													   + sizeof(struct ip_hdr));

	if (type == ECHO_REQUEST_TYPE && code == ECHO_REQUEST_CODE) {
		/* Creating a new buffer for the echo reply*/
		char reply_packet[MAX_PACKET_LEN];
		memset(reply_packet, 0, MAX_PACKET_LEN);

		/* Get the source MAC address of the router interface */
		uint8_t src_mac[MAC_ADDR_SIZE];
        get_interface_mac(interface, src_mac);

		/* Destination MAC is the source MAC address of the incoming packet */
        uint8_t *dst_mac = ether_header->ethr_shost;

        build_ethernet_header(reply_packet, src_mac, dst_mac, IPV4);

		struct ip_hdr *reply_ip_hdr = (struct ip_hdr *)(reply_packet + sizeof(struct ether_hdr));
        uint32_t src_ip = inet_addr(get_interface_ip(interface));
        uint32_t dst_ip = ip_header->source_addr;
        uint16_t total_len = sizeof(struct ip_hdr) + sizeof(struct icmp_hdr)
		 					+ (len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)
							- sizeof(struct icmp_hdr));
        build_ip_header(reply_ip_hdr, src_ip, dst_ip, total_len, DEFAULT_TTL, 1);

		struct icmp_hdr *reply_icmp_hdr = (struct icmp_hdr *)(reply_packet
										   + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
		reply_icmp_hdr->mtype = ECHO_REPLY_TYPE;
		reply_icmp_hdr->mcode = ECHO_REPLY_CODE;
		reply_icmp_hdr->un_t.echo_t.id = icmp_header->un_t.echo_t.id;
		reply_icmp_hdr->un_t.echo_t.seq = icmp_header->un_t.echo_t.seq;

		/* Copy the original ICMP data into the reply */
		size_t icmp_payload_len = len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)
								- sizeof(struct icmp_hdr);
		memcpy((char *)(reply_icmp_hdr + 1), (char *)(icmp_header + 1), icmp_payload_len);

		/* Recalculate the ICMP checksum for the reply */
		reply_icmp_hdr->check = 0;
		reply_icmp_hdr->check = htons(checksum((uint16_t *)reply_icmp_hdr,
									  sizeof(struct icmp_hdr) + icmp_payload_len));

		send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr)
					 + icmp_payload_len, reply_packet, interface);
	}

	/* Handle Destination Unreachable or Time Exceeded errors */
	if ((type == DESTINATION_UNREACHABLE_TYPE && code == DESTINATION_UNREACHABLE_CODE) ||
		(type == TIME_EXCEEDED_TYPE && code == TIME_EXCEEDED_CODE)) {
		/* Create a buffer for the error message */
		char icmp_packet[MAX_PACKET_LEN];
		memset(icmp_packet, 0, MAX_PACKET_LEN);

		uint8_t src_mac[MAC_ADDR_SIZE];
		get_interface_mac(interface, src_mac);

		uint8_t dst_mac[MAC_ADDR_SIZE];
		memcpy(dst_mac, ether_header->ethr_shost, MAC_ADDR_SIZE);

		build_ethernet_header(icmp_packet, src_mac, dst_mac, IPV4);

		struct ip_hdr *icmp_ip_hdr = (struct ip_hdr *)(icmp_packet + sizeof(struct ether_hdr));
        uint32_t src_ip = inet_addr(get_interface_ip(interface));
        uint32_t dst_ip = ip_header->source_addr;
        uint16_t total_len = sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8;
        build_ip_header(icmp_ip_hdr, src_ip, dst_ip, total_len, DEFAULT_TTL, 1);

		struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(icmp_packet 
									+ sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
		icmp_hdr->mtype = type;
		icmp_hdr->mcode = code;
		icmp_hdr->check = 0;
		icmp_hdr->un_t.echo_t.id = 0;
		icmp_hdr->un_t.echo_t.seq = 0;

		/* Copy the original IP header from the incoming packet to the ICMP message */
		char *icmp_data = (char *)(icmp_hdr + 1);
		size_t original_ip_header_len = ip_header->ihl * 4;
		memcpy(icmp_data, ip_header, original_ip_header_len);

		/* Copy up to 8 bytes of the original payload into the ICMP error message */
		size_t payload_len = len - sizeof(struct ether_hdr) - original_ip_header_len;
		if (payload_len > 8) {
			payload_len = 8;
		}
		memcpy(icmp_data + original_ip_header_len,
			   buf + sizeof(struct ether_hdr) + original_ip_header_len, payload_len);

		size_t icmp_total_len = sizeof(struct icmp_hdr)
								+ original_ip_header_len + payload_len;

		/* Recalculate the checksum for the ICMP error message */
		icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, icmp_total_len));

		send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + icmp_total_len,
					 icmp_packet, interface);
	}
}

/* Function to analyze the IPv4 packet */
void analyze_ipv4_packet(char *buf, size_t len, size_t interface) {
	struct ether_hdr *ether_header = (struct ether_hdr *)buf;
	struct ip_hdr *ip_header = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

    /* Check if the protocol is icmp and handle the echo request, if there is one */
	if (ip_header->proto == 1 &&
		ip_header->dest_addr == inet_addr(get_interface_ip(interface))) {
		struct icmp_hdr *icmp_header = (struct icmp_hdr *)
									   (buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
		if (icmp_header->mtype == ECHO_REQUEST_TYPE &&
		    icmp_header->mcode == ECHO_REQUEST_CODE) {
			analyze_icmp_packet(buf, len, interface, ECHO_REQUEST_TYPE, ECHO_REQUEST_CODE);
			return;
		}
	}

	uint16_t received_checksum = ntohs(ip_header->checksum);
	ip_header->checksum = 0;
	uint16_t calculated_checksum = checksum((uint16_t *)ip_header,
											sizeof(struct ip_hdr));

	/* Check if the checksum is the same as the one received in the ip header */
	if (received_checksum != calculated_checksum) {
		return;
	}

	if (ip_header->ttl <= 1) {
		/* "Time exceeded" icmp error */
		analyze_icmp_packet(buf, len, interface,
							TIME_EXCEEDED_TYPE, TIME_EXCEEDED_CODE);
		return;
	} else {
		ip_header->ttl = ip_header->ttl - 1;
	}

    /* Recalculate the checksum after changing the ttl */
	ip_header->checksum = htons(checksum((uint16_t *)ip_header,
										 sizeof(struct ip_hdr)));

	/* Search the routing table for a match based on the destination address,
	prefix, and mask */
	struct route_table_entry *route = trie_search(trie_root, ip_header->dest_addr);

	if (!route) {
		/* "Destination unreachable" icmp error */
		analyze_icmp_packet(buf, len, interface, DESTINATION_UNREACHABLE_TYPE,
		 					DESTINATION_UNREACHABLE_CODE);
		return;
	}

	/* Update L2 addresses: Set source MAC to router's interface, destination MAC
	 using ARP */
	update_next_hop_addresses(ether_header, route, buf);

	send_to_link(len, buf, route->interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	size_t len = 0;
	int interface = 0;

	init(argv + 2, argc - 2);

	rtable = malloc(MAX_ENTRIES * sizeof(struct route_table_entry));
	rtable_length = read_rtable(argv[1], rtable);

	trie_root = trie_create();
	for (int i = 0; i < rtable_length; i++) {
		trie_insert(trie_root, &rtable[i]);
	}

	arp_table = malloc(MAX_ENTRIES * sizeof(struct arp_table_entry));
	arp_table_length = parse_arp_table("arp_table.txt", arp_table);

	while (1) {
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_hdr *ether_header = (struct ether_hdr *)buf;
		uint16_t eth_type = ntohs(ether_header->ethr_type);

		uint8_t interface_mac[6];
		get_interface_mac(interface, interface_mac);
			
		int is_router_dest = 0;
		for (int i = 0; i < MAC_ADDR_SIZE; ++i) {
			if (ether_header->ethr_dhost[i] == interface_mac[i]) {
				is_router_dest = 1;
				break;
			}
		}

		if (!is_router_dest && !is_broadcast_mac(ether_header->ethr_dhost)) {
				continue;
		}
		
		if (eth_type == IPV4) {
			analyze_ipv4_packet(buf, len, interface);
		} else if (eth_type == ARP) {
			continue;
		}
	}
	trie_free(trie_root);
}