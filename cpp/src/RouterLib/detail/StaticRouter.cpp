#include "StaticRouter.h"
#include "protocol.h"
#include "utils.h"

#include <spdlog/spdlog.h>
#include <cstring>
#include <algorithm>
#include <netinet/in.h>

// Helper to send ICMP Error/Reply
// For Echo Reply: Type 0, Code 0. Payload = original data.
// For Errors (Type 3, 11): Payload = IP header + 8 bytes of original data.
static void sendIcmp(
    std::shared_ptr<IPacketSender> packetSender,
    std::shared_ptr<IRoutingTable> routingTable,
    ArpCache* arpCache,
    const Packet& original_packet,
    uint8_t type,
    uint8_t code,
    const std::string& incoming_iface_name = "") 
{
    if (original_packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;

    auto* orig_eth = reinterpret_cast<const sr_ethernet_hdr_t*>(original_packet.data());
    auto* orig_ip = reinterpret_cast<const sr_ip_hdr_t*>(original_packet.data() + sizeof(sr_ethernet_hdr_t));

    uint32_t dest_ip = orig_ip->ip_src;
    uint32_t src_ip; 

    // Determine Source IP for ICMP message
    if (type == 0) { // Echo Reply
        src_ip = orig_ip->ip_dst; // Reply from the IP it was sent to
    } else {
        // For errors, use the IP of the interface the packet arrived on (if we know it)
        // OR the IP of the outgoing interface?
        // RFC 1812: Source address should be the address of the interface on which the packet 
        // causing the error was received.
        if (!incoming_iface_name.empty()) {
            src_ip = routingTable->getRoutingInterface(incoming_iface_name).ip;
        } else {
            // Fallback: find route to dest and use outgoing interface IP
            auto route = routingTable->getRoutingEntry(dest_ip);
            if (route) {
                src_ip = routingTable->getRoutingInterface(route->iface).ip;
            } else {
                return; // Can't route back
            }
        }
    }
    
    // Find route to destination
    auto route = routingTable->getRoutingEntry(dest_ip);
    if (!route) return; // No route back

    std::string out_iface_name = route->iface;
    auto out_iface = routingTable->getRoutingInterface(out_iface_name);

    // Construct Packet
    // Size depends on type
    size_t icmp_payload_len = 0;
    size_t icmp_hdr_len = 0; // struct size (includes some data array usually)
    
    if (type == 0) {
        // Echo Reply: Header + Data from original ICMP
        // Original ICMP starts at +sizeof(eth) + sizeof(ip).
        // We need to parse original ICMP to get length?
        // Original packet length - eth - ip.
        size_t avail = original_packet.size() - sizeof(sr_ethernet_hdr_t) - (orig_ip->ip_hl * 4);
        icmp_payload_len = avail; 
        // Note: avail includes the 8 bytes of ICMP header + data.
        // sr_icmp_hdr_t is 4 bytes? No, 8 bytes (type, code, sum, id, seq).
        // struct sr_icmp_hdr has type, code, sum (4 bytes). Wait.
        // RFC 792: Echo Reply: Type(1), Code(1), Checksum(2), ID(2), Seq(2), Data(...).
        // protocol.h `sr_icmp_hdr` only has type, code, sum. It is incomplete for Echo.
        // We can just copy the whole ICMP payload from the original packet (including ID/Seq/Data) 
        // and just change Type/Code/Checksum.
    } else {
        // Error: Unused(4) + IP Header + 8 bytes.
        // sr_icmp_t3_hdr covers this (type, code, sum, unused, next_mtu, data[28]).
        // 28 bytes covers IP(20) + 8 bytes.
        // What if IP options? IP header > 20.
        // We just copy IP header + 8 bytes of data.
        // The struct has fixed size data array. 
        // We should just use a buffer.
    }
    
    // Simplified construction based on type
    Packet packet;
    size_t ip_len_field = 0;

    if (type == 0) {
        // Echo Reply
        packet.resize(original_packet.size());
        // Copy everything first
        memcpy(packet.data(), original_packet.data(), original_packet.size());
        
        auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
        auto* ip = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        // ICMP starts after IP
        auto* icmp_hdr = reinterpret_cast<sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + (ip->ip_hl * 4));
        
        // Update ICMP
        icmp_hdr->icmp_type = 0;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_sum = 0;
        
        // Calc checksum over ICMP part
        size_t icmp_part_len = packet.size() - (sizeof(sr_ethernet_hdr_t) + (ip->ip_hl * 4));
        icmp_hdr->icmp_sum = cksum(icmp_hdr, icmp_part_len);
        
        // Update IP
        ip->ip_src = src_ip;
        ip->ip_dst = dest_ip;
        ip->ip_sum = 0;
        ip->ip_sum = cksum(ip, ip->ip_hl * 4);
        
        ip_len_field = ntohs(ip->ip_len); // Should be same as original
        
    } else {
        // Error
        // Eth(14) + IP(20) + ICMP Type 3 Header (8) + Original IP Header + 8 bytes.
        // sr_icmp_t3_hdr is 36 bytes (8 header + 28 data).
        // Total IP payload = 36 bytes.
        // Total IP size = 20 + 36 = 56.
        // Total Packet = 14 + 56 = 70.
        
        packet.resize(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        
        auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
        auto* ip = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        auto* icmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        
        // ICMP
        icmp->icmp_type = type;
        icmp->icmp_code = code;
        icmp->unused = 0;
        icmp->next_mtu = 0;
        icmp->icmp_sum = 0;
        
        // Copy Original IP + 8 bytes
        const uint8_t* copy_src = original_packet.data() + sizeof(sr_ethernet_hdr_t);
        size_t copy_len = std::min((size_t)ICMP_DATA_SIZE, original_packet.size() - sizeof(sr_ethernet_hdr_t));
        memset(icmp->data, 0, ICMP_DATA_SIZE);
        memcpy(icmp->data, copy_src, copy_len);
        
        icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));
        
        // IP
        ip->ip_hl = 5;
        ip->ip_v = 4;
        ip->ip_tos = 0;
        ip->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
        ip->ip_id = 0;
        ip->ip_off = htons(IP_DF);
        ip->ip_ttl = 64;
        ip->ip_p = ip_protocol_icmp;
        ip->ip_src = src_ip;
        ip->ip_dst = dest_ip;
        ip->ip_sum = 0;
        ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));
    }

    // Send
    uint32_t next_hop = route->gateway ? route->gateway : dest_ip;
    auto mac = arpCache->getEntry(next_hop);
    
    if (mac) {
        auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
        memcpy(eth->ether_dhost, mac->data(), ETHER_ADDR_LEN);
        memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);
        eth->ether_type = htons(ethertype_ip);
        packetSender->sendPacket(packet, out_iface_name);
    } else {
        arpCache->queuePacket(next_hop, packet, out_iface_name);
    }
}

StaticRouter::StaticRouter(
    std::unique_ptr<ArpCache> arpCache, 
    std::shared_ptr<IRoutingTable> routingTable,
    std::shared_ptr<IPacketSender> packetSender)
: routingTable(std::move(routingTable))
, packetSender(std::move(packetSender))
, arpCache(std::move(arpCache)) {
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface) {
    std::unique_lock lock(mutex); // Protect router state if any (ArpCache has its own locks)

    if (packet.size() < sizeof(sr_ethernet_hdr_t)) return;

    auto* eth_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t ethtype = ntohs(eth_hdr->ether_type);

    if (ethtype == ethertype_arp) {
        if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) return;
        
        auto* arp_hdr = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        uint16_t op = ntohs(arp_hdr->ar_op);
        
        if (op == arp_op_request) {
            // Is it for us?
            uint32_t tip = arp_hdr->ar_tip;
            
            // Check all interfaces
            bool target_is_me = false;
            mac_addr target_mac;
            
            for (const auto& [name, interface] : routingTable->getRoutingInterfaces()) {
                if (interface.ip == tip) {
                    target_is_me = true;
                    target_mac = interface.mac;
                    break;
                }
            }
            
            if (target_is_me) {
                // Send Reply
                Packet reply(packet.size());
                memcpy(reply.data(), packet.data(), packet.size());
                
                auto* r_eth = reinterpret_cast<sr_ethernet_hdr_t*>(reply.data());
                auto* r_arp = reinterpret_cast<sr_arp_hdr_t*>(reply.data() + sizeof(sr_ethernet_hdr_t));
                
                // Update Ethernet
                memcpy(r_eth->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
                memcpy(r_eth->ether_shost, target_mac.data(), ETHER_ADDR_LEN);
                
                // Update ARP
                r_arp->ar_op = htons(arp_op_reply);
                memcpy(r_arp->ar_sha, target_mac.data(), ETHER_ADDR_LEN);
                r_arp->ar_sip = tip;
                memcpy(r_arp->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                r_arp->ar_tip = arp_hdr->ar_sip;
                
                packetSender->sendPacket(reply, iface);
            }
        } else if (op == arp_op_reply) {
            // Add to cache
            mac_addr sha;
            memcpy(sha.data(), arp_hdr->ar_sha, ETHER_ADDR_LEN);
            arpCache->addEntry(arp_hdr->ar_sip, sha);
        }
        
    } else if (ethtype == ethertype_ip) {
        if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;
        
        auto* ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
        
        // Verify checksum
        uint16_t old_sum = ip_hdr->ip_sum;
        ip_hdr->ip_sum = 0;
        if (cksum(ip_hdr, ip_hdr->ip_hl * 4) != old_sum) {
            return; // Drop
        }
        ip_hdr->ip_sum = old_sum; // Restore
        
        uint32_t dst = ip_hdr->ip_dst;
        
        // Check if destined for us
        bool for_me = false;
        for (const auto& [name, interface] : routingTable->getRoutingInterfaces()) {
            if (interface.ip == dst) {
                for_me = true;
                break;
            }
        }
        
        if (for_me) {
            if (ip_hdr->ip_p == ip_protocol_icmp) {
                // Is it Echo Request?
                // Header len can be variable
                auto* icmp_hdr = reinterpret_cast<sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
                // Check bounds
                if ((uint8_t*)icmp_hdr + sizeof(sr_icmp_hdr_t) <= packet.data() + packet.size()) {
                    if (icmp_hdr->icmp_type == 8) {
                        // Verify ICMP checksum
                        uint16_t old_icmp_sum = icmp_hdr->icmp_sum;
                        icmp_hdr->icmp_sum = 0;
                        size_t icmp_len = packet.size() - (sizeof(sr_ethernet_hdr_t) + (ip_hdr->ip_hl * 4));
                        if (cksum(icmp_hdr, icmp_len) == old_icmp_sum) {
                            // Send Reply
                            sendIcmp(packetSender, routingTable, arpCache.get(), packet, 0, 0, iface);
                        }
                    }
                }
            } else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
                // Port Unreachable
                sendIcmp(packetSender, routingTable, arpCache.get(), packet, 3, 3, iface);
            }
        } else {
            // Forwarding
            if (ip_hdr->ip_ttl <= 1) {
                sendIcmp(packetSender, routingTable, arpCache.get(), packet, 11, 0, iface);
                return;
            }
            
            ip_hdr->ip_ttl--;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
            
            auto route = routingTable->getRoutingEntry(dst);
            if (!route) {
                sendIcmp(packetSender, routingTable, arpCache.get(), packet, 3, 0, iface);
                return;
            }
            
            uint32_t next_hop = route->gateway ? route->gateway : dst;
            auto out_iface = routingTable->getRoutingInterface(route->iface);
            
            auto mac = arpCache->getEntry(next_hop);
            if (mac) {
                memcpy(eth_hdr->ether_dhost, mac->data(), ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);
                packetSender->sendPacket(packet, route->iface);
            } else {
                arpCache->queuePacket(next_hop, packet, route->iface);
            }
        }
    }
}
