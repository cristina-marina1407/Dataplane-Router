## Tema 1 PCOM - Dataplane Router

    This project implements the dataplane component of a router using C. In my
implementation I only use the static ARP table, using the parse_arp_table
function provided in the homework resources. Besides that, the router handles
IPv4 packets and selectively responds to ICMP messages, such as Echo Request, 
Destination Unreachable and Time Exceeded.
    First of all, my code uses global variables for the routing and arp tables
and their lengths. The `main` function reads these tables and determines what
type of packet we have to deal with. It checks if the received packet is for this
router by comparing the destination MAC address with the interface's MAC address
or by checking if the address is a broadcast address. The broadcast verification 
is done using a helper function called `is_broadcast_mac()`.
    In addition to this, the program also uses a trie data structure to efficently
find the best route, the longest prefix match, in the routing table. The functions
that handle the trie implementation are located in the `trie.c` and `trie.h` files.
The trie is constructed using the `trie_insert()` function where each node represents
a bit of the prefix. To find the best route for a given destination IP address,
the code uses the `trie_search()` function that traverses the trie bit by bit in
order to select the longest prefix match.

    The implementation uses two functions to handle the ipv4 packets:
- `analyze_ipv4_packet`
    This function checks if the ip header has a icmp protocol with the echo request
    type and handles it properly if it does. Then it checks if the checksum is
    valid and if the ttl is not 0 or 1, if that's the case it sends an icmp
    error message. Otherwise, the ttl is decrementated and the checksum is
    recalculated accordingly. The function uses the trie to find the best route.
    If a matching route is found, it updates the ethernet header with the correct
    MAC addresses using the `update_next_hop_addresse` function and forwards the
    packet through the corresponding interface. If no route is found, the function
    responds with an icmp error message, "Destination Unreachable".
    
- `analyze_icmp_packet`
    This function is handling the icmp packets by responding to the Echo Request,
    Destination Unreachable, or Time Exceeded icmp protocol types.
    When the received packet is an Echo Request, the function constructs a new Echo
    Reply message. It allocates a new buffer for the reply and then updates
    the ethernet, ip and icmp headers. The source and destination MAC addresses
    are switched, the ICMP header is filled with the reply type and code, the
    identifier and sequence number are copied from the original request,
    and a new checksum is calculated. Finally, the response is sent through the
    correct interface.
    When the received packet is an icmp error, the function allocates a new buffer,
    builds an icmp error message containing the original ip header and the first
    8 bytes of the payload as required.
    To build the ethernet and ip header are used the `build_ethernet_header` and
    `build_ip_header` helper functions. 

