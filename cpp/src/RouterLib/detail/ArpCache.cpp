#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <algorithm>
#include <spdlog/spdlog.h>
#include <netinet/in.h>

#include "protocol.h"
#include "utils.h"

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

void ArpCache::sendArpRequest(uint32_t ip, const std::string& iface) {
    auto routingInterface = routingTable->getRoutingInterface(iface);

    Packet packet(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    std::memset(packet.data(), 0, packet.size());

    auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    auto* arp = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

    std::memset(eth->ether_dhost, 0xFF, ETHER_ADDR_LEN);
    std::memcpy(eth->ether_shost, routingInterface.mac.data(), ETHER_ADDR_LEN);
    eth->ether_type = htons(ethertype_arp);

    arp->ar_hrd = htons(arp_hrd_ethernet);
    arp->ar_pro = htons(ethertype_ip);
    arp->ar_hln = ETHER_ADDR_LEN;
    arp->ar_pln = 4;
    arp->ar_op = htons(arp_op_request);
    std::memcpy(arp->ar_sha, routingInterface.mac.data(), ETHER_ADDR_LEN);
    arp->ar_sip = routingInterface.ip;
    std::memset(arp->ar_tha, 0, ETHER_ADDR_LEN);
    arp->ar_tip = ip;

    packetSender->sendPacket(packet, iface);
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);
    auto now = std::chrono::steady_clock::now();
    std::vector<uint32_t> expired;

    for (auto& [ip, req] : requests) {
        if (now - req.lastSent >= resendInterval) {
            if (req.timesSent >= 7) {
                expired.push_back(ip);
            } else {
                sendArpRequest(req.ip, req.iface);
                req.lastSent = now;
                req.timesSent++;
            }
        }
    }

    for (uint32_t ip : expired) {
        auto node = requests.extract(ip);
        auto& req = node.mapped();

        for (const auto& pkt : req.packets) {
            if (pkt.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) continue;

            const auto* orig_eth = reinterpret_cast<const sr_ethernet_hdr_t*>(pkt.data());
            const auto* orig_ip = reinterpret_cast<const sr_ip_hdr_t*>(pkt.data() + sizeof(sr_ethernet_hdr_t));

            Packet response(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(response.data());
            auto* ip_hdr = reinterpret_cast<sr_ip_hdr_t*>(response.data() + sizeof(sr_ethernet_hdr_t));
            auto* icmp = reinterpret_cast<sr_icmp_t3_hdr_t*>(response.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

            auto out_iface = routingTable->getRoutingInterface(req.iface);

            std::memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);
            std::memcpy(eth->ether_dhost, orig_eth->ether_shost, ETHER_ADDR_LEN);
            eth->ether_type = htons(ethertype_ip);

            ip_hdr->ip_hl = 5;
            ip_hdr->ip_v = 4;
            ip_hdr->ip_tos = 0;
            ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
            ip_hdr->ip_id = 0;
            ip_hdr->ip_off = htons(IP_DF);
            ip_hdr->ip_ttl = INIT_TTL;
            ip_hdr->ip_p = ip_protocol_icmp;
            ip_hdr->ip_src = out_iface.ip;
            ip_hdr->ip_dst = orig_ip->ip_src;
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

            icmp->icmp_type = 3;
            icmp->icmp_code = 1;
            icmp->unused = 0;
            icmp->next_mtu = 0;
            std::memcpy(icmp->data, orig_ip, sizeof(sr_ip_hdr_t) + 8);
            icmp->icmp_sum = 0;
            icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));

            packetSender->sendPacket(response, req.iface);
        }
    }

    std::erase_if(entries, [this, now](const auto& e) {
        return now - e.second.timeAdded >= entryTimeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);
    auto it = requests.find(ip);
    if (it == requests.end()) return;

    entries[ip] = {std::chrono::steady_clock::now(), mac};
    auto out_iface = routingTable->getRoutingInterface(it->second.iface);

    for (auto& pkt : it->second.packets) {
        auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(pkt.data());
        std::memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);
        std::memcpy(eth->ether_dhost, mac.data(), ETHER_ADDR_LEN);
        packetSender->sendPacket(pkt, it->second.iface);
    }

    requests.erase(it);
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);
    auto it = entries.find(ip);
    if (it == entries.end()) return std::nullopt;
    return it->second.mac;
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);

    if (auto it = entries.find(ip); it != entries.end()) {
        Packet pkt = packet;
        auto* eth = reinterpret_cast<sr_ethernet_hdr_t*>(pkt.data());
        auto out_iface = routingTable->getRoutingInterface(iface);
        std::memcpy(eth->ether_shost, out_iface.mac.data(), ETHER_ADDR_LEN);
        std::memcpy(eth->ether_dhost, it->second.mac.data(), ETHER_ADDR_LEN);
        packetSender->sendPacket(pkt, iface);
        return;
    }

    auto& req = requests[ip];
    if (req.timesSent == 0) {
        req.ip = ip;
        req.iface = iface;
        req.timesSent = 1;
        req.lastSent = std::chrono::steady_clock::now();
        sendArpRequest(ip, iface);
    }
    req.packets.push_back(packet);
}
