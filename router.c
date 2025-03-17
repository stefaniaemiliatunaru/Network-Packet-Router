#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
#define IPv4 0x0800

/* routing table */
struct route_table_entry *rtable;
int rtable_len;

/* MAC table */
struct arp_table_entry *arp_table;
int arp_table_len;

/* compare function for quicksort */
int compare_function(const void *first_entry, const void *second_entry) 
{
	struct route_table_entry *first_e = (struct route_table_entry *)first_entry;
	struct route_table_entry *second_e = (struct route_table_entry *)second_entry;
	if (ntohl(first_e->prefix & first_e->mask) < ntohl(second_e->prefix & second_e->mask))
	{
		return -1;
	}
	else if (ntohl(first_e->prefix & first_e->mask) > ntohl(second_e->prefix & second_e->mask))
	{
		return 1;
	}
	return ntohl(first_e->mask) - ntohl(second_e->mask);
}

/* LPM function - binary search */
struct route_table_entry *get_best_route(uint32_t ip_dest)
{
	struct route_table_entry *best_entry = NULL;
	int left = 0, right = rtable_len - 1;

	while (left <= right)
	{
		int middle = left + ((right - left) / 2);
		struct route_table_entry *entry = rtable + middle;

		if (ntohl(entry->prefix & entry->mask) > ntohl(ip_dest & entry->mask))
		{
			right = middle - 1;
		}
		else if (ntohl(entry->prefix & entry->mask) < ntohl(ip_dest & entry->mask))
		{
			left = middle + 1;
		}
		else
		{
			best_entry = rtable + middle;
			left = middle + 1;
		}
	}

	return best_entry;
}

/* function for finding address in MAC table */
struct arp_table_entry *get_arp_entry(uint32_t given_ip)
{
	for (int i = 0; i < arp_table_len; i++)
		if (arp_table[i].ip == given_ip)
			return &(arp_table[i]);
	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	if (!rtable) return 0;
	rtable_len = read_rtable(argv[1], rtable);

	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_function);

	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	if (!arp_table) return 0;
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1)
	{
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		/* check if packet is of IPv4 type */
		if (eth_hdr->ether_type == ntohs(IPv4))
		{
			/* check if this router is the destination of the packet */
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)))
			{
				size_t aux_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
				char *aux_buffer = malloc(MAX_PACKET_LEN * sizeof(char));
				if (aux_buffer == NULL) return 0;
				memcpy(aux_buffer, buf, MAX_PACKET_LEN);
				struct icmphdr *icmp_hdr = (struct icmphdr *)(aux_buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
				struct ether_header *aux_eth_hdr = (struct ether_header *)aux_buffer;
				struct iphdr *aux_ip_hdr = (struct iphdr *)(aux_buffer + sizeof(struct ether_header));
				icmp_hdr->type = 0;
				aux_ip_hdr->saddr = ip_hdr->daddr;
				aux_ip_hdr->daddr = ip_hdr->saddr;
				aux_ip_hdr->ttl = 64;
				icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));
				aux_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				aux_eth_hdr->ether_type = eth_hdr->ether_type;
				memcpy(aux_eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
				memcpy(aux_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				send_to_link(interface, aux_buffer, aux_len);
				free(aux_buffer);
				continue;
			}

			/* checksum */
			if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))
				continue;

			/* TLL check */
			if (ip_hdr->ttl <= 1)
			{
				size_t aux_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
				char *aux_buffer = malloc(MAX_PACKET_LEN * sizeof(char));
				if (aux_buffer == NULL) return 0;
				memcpy(aux_buffer, buf, MAX_PACKET_LEN);
				struct icmphdr *icmp_hdr = (struct icmphdr *)(aux_buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
				struct ether_header *aux_eth_hdr = (struct ether_header *)aux_buffer;
				struct iphdr *aux_ip_hdr = (struct iphdr *)(aux_buffer + sizeof(struct ether_header));
				icmp_hdr->type = 11;
				icmp_hdr->code = 0;
				aux_ip_hdr->saddr = ip_hdr->daddr;
				aux_ip_hdr->daddr = ip_hdr->saddr;
				aux_ip_hdr->ttl = 64;
				icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));
				aux_ip_hdr->protocol = 1;
				aux_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				aux_eth_hdr->ether_type = eth_hdr->ether_type;
				memcpy(aux_eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
				memcpy(aux_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				send_to_link(interface, aux_buffer, aux_len);
				free(aux_buffer);
				continue;
			}
			ip_hdr->ttl--;

			/* search in the routing table */
			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);
			if (best_route == NULL)
			{
				size_t aux_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
				char *aux_buffer = malloc(MAX_PACKET_LEN * sizeof(char));
				if (aux_buffer == NULL) return 0;
				memcpy(aux_buffer, buf, MAX_PACKET_LEN);
				struct icmphdr *icmp_hdr = (struct icmphdr *)(aux_buffer + sizeof(struct ether_header) + sizeof(struct iphdr));
				struct ether_header *aux_eth_hdr = (struct ether_header *)aux_buffer;
				struct iphdr *aux_ip_hdr = (struct iphdr *)(aux_buffer + sizeof(struct ether_header));
				icmp_hdr->type = 3;
				icmp_hdr->code = 0;
				aux_ip_hdr->saddr = ip_hdr->daddr;
				aux_ip_hdr->daddr = ip_hdr->saddr;
				aux_ip_hdr->ttl = 64;
				icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));
				aux_ip_hdr->protocol = 1;
				aux_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				aux_eth_hdr->ether_type = eth_hdr->ether_type;
				memcpy(aux_eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
				memcpy(aux_eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				send_to_link(interface, aux_buffer, aux_len);
				free(aux_buffer);
				continue;
			}

			/* update checksum */
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			/* source address will be the address of the router's interface to which the packet is sent */
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);

			/* destination address is the MAC address of the next hop */
			struct arp_table_entry *arp_entry = get_arp_entry(ip_hdr->daddr);
			if (arp_entry == NULL)
				continue;
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);

			/* send packet to the correspondent interface of the next hop */
			send_to_link(best_route->interface, buf, len);
		}
	}
	free(rtable);
	free(arp_table);
}