#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <algorithm>
#include <spdlog/spdlog.h>
#include <netinet/in.h>

#include "protocol.h"
#include "utils.h"


// Helper to send ARP Request
static void sendArpRequest(std::shared_ptr<IPacketSender> packetSender, 
                           std::shared_ptr<IRoutingTable> routingTable, 
                           uint32_t target_ip, 
                           const std::string& iface_name) {
    auto iface = routingTable->getRoutingInterface(iface_name);
    
    Packet packet(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    auto* arp = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    
    // Ethernet
    memset(eth->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(eth->ether_shost, iface.mac.data(), ETHER_ADDR_LEN);
    eth->ether_type = htons(ethertype_arp);
    
    // ARP
    arp->ar_hrd = htons(arp_hrd_ethernet);
    arp->ar_pro = htons(ethertype_ip);
    arp->ar_hln = ETHER_ADDR_LEN;
    arp->ar_pln = 4;
    arp->ar_op = htons(arp_op_request);
    memcpy(arp->ar_sha, iface.mac.data(), ETHER_ADDR_LEN);
    arp->ar_sip = iface.ip;
    memset(arp->ar_tha, 0x00, ETHER_ADDR_LEN);
    arp->ar_tip = target_ip;
    
    packetSender->sendPacket(packet, iface_name);
}

static void sendHostUnreachable(std::shared_ptr<IPacketSender> packetSender,
                                std::shared_ptr<IRoutingTable> routingTable,
                                ArpCache* cache,
                                const Packet& original_packet) {
    if (original_packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;
    
    auto* orig_ip = reinterpret_cast<const sr_ip_hdr_t*>(original_packet.data() + sizeof(sr_ethernet_hdr_t));
    uint32_t dest_ip = orig_ip->ip_src; // Send back to source
    
    auto route = routingTable->getRoutingEntry(dest_ip);
    if (!route) return;
    
    auto iface_name = route->iface;
    auto iface = routingTable->getRoutingInterface(iface_name);
    
    // Construct ICMP Type 3 packet
    size_t icmp_len = sizeof(sr_icmp_t3_hdr_t);
    size_t ip_len = sizeof(sr_ip_hdr_t);
    size_t eth_len = sizeof(sr_ethernet_hdr_t);
    
    Packet packet(eth_len + ip_len + icmp_len);
    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    auto* ip = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + eth_len);
    auto* icmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(packet.data() + eth_len + ip_len);
    
    // ICMP
    icmp->icmp_type = 3;
    icmp->icmp_code = 1; // Host unreachable
    icmp->unused = 0;
    icmp->next_mtu = 0;
    
    // Copy data
    const uint8_t* orig_data_ptr = original_packet.data() + eth_len;
    size_t copy_len = std::min((size_t)ICMP_DATA_SIZE, original_packet.size() - eth_len);
    memset(icmp->data, 0, ICMP_DATA_SIZE);
    memcpy(icmp->data, orig_data_ptr, copy_len);
    
    icmp->icmp_sum = 0;
    icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));
    
    // IP
    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(ip_len + icmp_len);
    ip->ip_id = 0; 
    ip->ip_off = htons(IP_DF);
    ip->ip_ttl = 64;
    ip->ip_p = ip_protocol_icmp;
    ip->ip_src = iface.ip;
    ip->ip_dst = dest_ip;
    ip->ip_sum = 0;
    ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));
    
    // Determine next hop and send/queue
    uint32_t next_hop = route->gateway ? route->gateway : dest_ip;
    
    auto mac = cache->getEntry(next_hop);
    if (mac) {
        memcpy(eth->ether_dhost, mac->data(), ETHER_ADDR_LEN);
        memcpy(eth->ether_shost, iface.mac.data(), ETHER_ADDR_LEN);
        eth->ether_type = htons(ethertype_ip);
        packetSender->sendPacket(packet, iface_name);
    } else {
        cache->queuePacket(next_hop, packet, iface_name);
    }
}


ArpCache::ArpCache(
    std::chrono::milliseconds entryTimeout, 
    std::chrono::milliseconds tickInterval, 
    std::chrono::milliseconds resendInterval,
    std::shared_ptr<IPacketSender> packetSender, 
    std::shared_ptr<IRoutingTable> routingTable)
: entryTimeout(entryTimeout)
, tickInterval(tickInterval)
, resendInterval(resendInterval)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(tickInterval);
    }
}

void ArpCache::tick() {
    std::vector<std::tuple<uint32_t, std::string>> to_resend;
    std::vector<Packet> dropped_packets; 
    
    {
        std::unique_lock lock(mutex);
        auto now = std::chrono::steady_clock::now();
        
        for (auto it = requests.begin(); it != requests.end(); ) {
            auto& req = it->second;
            if (now - req.lastSent >= resendInterval) {
                if (req.retries >= 7) {
                    // Timeout
                    dropped_packets.insert(dropped_packets.end(), req.waitingPackets.begin(), req.waitingPackets.end());
                    it = requests.erase(it);
                } else {
                    // Resend
                    req.lastSent = now;
                    req.retries++;
                    to_resend.emplace_back(it->first, req.iface); 
                    // Note: req.ip is target IP. 'it->first' is also target IP.
                    ++it;
                }
            } else {
                ++it;
            }
        }
        
        // Expire entries
        std::erase_if(entries, [this, now](const auto& entry) {
             return now - entry.second.timeAdded >= entryTimeout;
        });
    }
    
    // Perform actions without lock
    for (const auto& [ip, iface] : to_resend) {
        sendArpRequest(packetSender, routingTable, ip, iface);
    }
    
    for (const auto& packet : dropped_packets) {
        sendHostUnreachable(packetSender, routingTable, this, packet);
    }
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::vector<Packet> packetsToSend;
    std::string ifaceName;
    
    {
        std::unique_lock lock(mutex);
        
        entries[ip] = {std::chrono::steady_clock::now(), mac};
        
        auto it = requests.find(ip);
        if (it != requests.end()) {
            packetsToSend = std::move(it->second.waitingPackets);
            ifaceName = it->second.iface;
            requests.erase(it);
        }
    }
    
    if (!packetsToSend.empty()) {
        auto iface = routingTable->getRoutingInterface(ifaceName);
        for (auto& packet : packetsToSend) {
            if (packet.size() < sizeof(sr_ethernet_hdr_t)) continue;
            
            auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
            memcpy(eth->ether_dhost, mac.data(), ETHER_ADDR_LEN);
            memcpy(eth->ether_shost, iface.mac.data(), ETHER_ADDR_LEN);
            eth->ether_type = htons(ethertype_ip);
            
            packetSender->sendPacket(packet, ifaceName);
        }
    }
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);
    
    auto it = entries.find(ip);
    if (it != entries.end()) {
        return it->second.mac;
    }

    return std::nullopt; 
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    bool shouldSendArp = false;
    
    {
        std::unique_lock lock(mutex);
        
        auto it = requests.find(ip);
        if (it != requests.end()) {
            it->second.waitingPackets.push_back(packet);
        } else {
            ArpRequest req;
            // req.ip = ip; 
            req.lastSent = std::chrono::steady_clock::now();
            req.retries = 1;
            req.iface = iface;
            req.waitingPackets.push_back(packet);
            
            requests[ip] = std::move(req);
            shouldSendArp = true;
        }
    }
    
    if (shouldSendArp) {
        sendArpRequest(packetSender, routingTable, ip, iface);
    }
}
