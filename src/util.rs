use std::net::Ipv4Addr;
use pnet::packet::{icmp, ipv4::{Ipv4Packet, MutableIpv4Packet}, tcp::{self, MutableTcpPacket, TcpPacket}, udp::{self, MutableUdpPacket, UdpPacket}, Packet};
use pnet::packet::icmp::{IcmpTypes, IcmpPacket, MutableIcmpPacket, echo_reply::{EchoReplyPacket, MutableEchoReplyPacket}, echo_request::{EchoRequestPacket, MutableEchoRequestPacket}};

pub mod port_range {
    pub fn gen(cycle_size: u16, cycle_nums: u16, cycle_starts: u16, portset_offset: u16, portset_size: u16) -> Vec<u16>{
        let mut range:Vec<u16>=Vec::new();
        for n in 0..cycle_nums{
            let begin = cycle_starts+(n*cycle_size)+portset_offset;
            let mut v = (begin..begin+portset_size-1).collect();
            range.append(&mut v);
        }
        range
    }
    #[allow(dead_code)]
    pub fn gen_v6plus(psid: u8) -> Vec<u16>{
        gen(4096, 15, 4096, (psid as u16)<<4, 16)
    }
    #[allow(dead_code)]
    ///max 63
    pub fn gen_ocn_vc(psid: u8) -> Vec<u16>{
        gen(1024, 63, 1024, (psid as u16)<<4, 16)
    }
}

//An entry has information of the packet that initially triggered creation of the entry
pub struct NatEntry<LD> {
    pub create_at: u64,
    pub last_egress: u64,
    pub nat_key: LD,
    pub local_tuple: (Ipv4Addr, u16),
    pub global_port: u16,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub bytes_sent: u32,
    pub bytes_received: u32,
}
impl<LD>NatEntry<LD>{
    pub fn new(t: u64, nat_key: LD, local_tuple:(Ipv4Addr, u16), global_port: u16) -> Self{
        Self{nat_key: nat_key, local_tuple: local_tuple, global_port: global_port, 
            create_at: t, last_egress: t, packets_sent: 0, packets_received: 0, bytes_sent: 0, bytes_received: 0}
    }
}
pub struct PacketInfo {
    pub src_tuple: (Ipv4Addr, u16),
    pub dst_tuple: (Ipv4Addr, u16),
    pub size: u16
}
impl PacketInfo{
    pub fn dummy() -> Self{
        Self{src_tuple: (Ipv4Addr::new(0, 0, 0, 0),0) , dst_tuple: (Ipv4Addr::new(0, 0, 0, 0),0), size: 0}
    }
}
pub trait PortManager{
    fn get_info(packet: &Ipv4Packet) -> PacketInfo;
    fn set_src_port(packet: MutableIpv4Packet, val:u16) -> Option<MutableIpv4Packet>;//Do NOT use this for ICMP Echo Reply
    fn set_dst_port(packet: MutableIpv4Packet, val:u16) -> Option<MutableIpv4Packet>;//Do NOT use this for ICMP Echo Request
    fn correct_checksum(packet: MutableIpv4Packet) -> Option<MutableIpv4Packet>;
}
pub struct TcpPortManager;
pub struct UdpPortManager;
pub struct IcmpEchoPortManager;
impl PortManager for TcpPortManager{
    fn get_info(packet: &Ipv4Packet) -> PacketInfo{
        if let Some(tcp) = TcpPacket::new(packet.payload()){
            PacketInfo{src_tuple: (packet.get_source(), tcp.get_source()), dst_tuple: (packet.get_destination(), tcp.get_destination()), size: packet.get_total_length()}
        }else{
            PacketInfo::dummy()
        }
    }
    fn set_src_port(mut packet: MutableIpv4Packet, val:u16) -> Option<MutableIpv4Packet>{
        let mut aa = packet.payload().to_vec();
        let mut a = MutableTcpPacket::new(aa.as_mut_slice()).unwrap(); a.set_source(val);packet.set_payload(a.packet());
        Some(packet)
    }
    fn set_dst_port(mut packet: MutableIpv4Packet, val:u16) -> Option<MutableIpv4Packet>{
        let mut aa = packet.payload().to_vec();
        let mut a = MutableTcpPacket::new(aa.as_mut_slice()).unwrap(); a.set_destination(val);packet.set_payload(a.packet());
        Some(packet)
    }
    fn correct_checksum(mut packet: MutableIpv4Packet) -> Option<MutableIpv4Packet>{
        let mut aa = packet.payload().to_vec();
        let mut a = MutableTcpPacket::new(aa.as_mut_slice()).unwrap(); 
        a.set_checksum(tcp::ipv4_checksum(&a.to_immutable(), &packet.get_source(), &packet.get_destination()));
        packet.set_payload(a.packet());
        Some(packet)
    }
    
}


impl PortManager for UdpPortManager{
    fn get_info(packet: &Ipv4Packet) -> PacketInfo{
        if let Some(tcp) = UdpPacket::new(packet.payload()){
            PacketInfo{src_tuple: (packet.get_source(), tcp.get_source()), dst_tuple: (packet.get_destination(), tcp.get_destination()), size: packet.get_total_length()}
        }else{
            PacketInfo::dummy()
        }
    }
    fn set_src_port(mut packet: MutableIpv4Packet, val:u16) -> Option<MutableIpv4Packet>{
        let mut aa = packet.payload().to_vec();
        let mut a = MutableUdpPacket::new(aa.as_mut_slice()).unwrap(); a.set_source(val);packet.set_payload(a.packet());
        Some(packet)
    }
    fn set_dst_port(mut packet: MutableIpv4Packet, val:u16) -> Option<MutableIpv4Packet>{
        let mut aa = packet.payload().to_vec();
        let mut a = MutableUdpPacket::new(aa.as_mut_slice()).unwrap(); a.set_destination(val);packet.set_payload(a.packet());
        Some(packet)
    }
    fn correct_checksum(mut packet: MutableIpv4Packet) -> Option<MutableIpv4Packet>{
        let mut aa = packet.payload().to_vec();
        let mut a = MutableUdpPacket::new(aa.as_mut_slice()).unwrap(); a.set_checksum(udp::ipv4_checksum(&a.to_immutable(), &packet.get_source(), &packet.get_destination()));packet.set_payload(a.packet());
        Some(packet)
    }
}

impl PortManager for IcmpEchoPortManager{
    fn get_info(packet: &Ipv4Packet) -> PacketInfo{
        if let Some(icmp) =IcmpPacket::new(packet.payload()){
            let (sport, dport) = match icmp.get_icmp_type() {
                IcmpTypes::EchoRequest => {
                    (EchoRequestPacket::new(packet.payload()).unwrap().get_identifier(), 0)
                },
                IcmpTypes::EchoReply => {
                    (0, EchoReplyPacket::new(packet.payload()).unwrap().get_identifier())
                },
                _ => (0, 0)
            };
            PacketInfo{src_tuple: (packet.get_source(),sport), dst_tuple: (packet.get_destination(),dport), size: packet.get_total_length()}
        }else{
            PacketInfo::dummy()
        }
    }
    fn set_src_port(mut packet: MutableIpv4Packet, val:u16) -> Option<MutableIpv4Packet>{
        let mut aa = packet.payload().to_vec();
        let mut a = MutableEchoRequestPacket::new(aa.as_mut_slice()).unwrap(); a.set_identifier(val);
        packet.set_payload(a.packet());
        Some(packet)
    }
    fn set_dst_port(mut packet: MutableIpv4Packet, val:u16) -> Option<MutableIpv4Packet>{
        let mut aa = packet.payload().to_vec();
        let mut a = MutableEchoReplyPacket::new(aa.as_mut_slice()).unwrap(); a.set_identifier(val);
        packet.set_payload(a.packet());
        Some(packet)
    }
    fn correct_checksum(mut packet: MutableIpv4Packet) -> Option<MutableIpv4Packet>{
        let mut aa = packet.payload().to_vec();
        let mut a = MutableIcmpPacket::new(aa.as_mut_slice()).unwrap(); a.set_checksum(icmp::checksum(&a.to_immutable()));packet.set_payload(a.packet());
        Some(packet)
    }
}
