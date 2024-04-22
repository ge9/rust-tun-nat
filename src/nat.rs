
use crate::HashNATTable;
use crate::keygen::KeyGen;
use crate::TcpStateHashNATTable;
use crate::util::{PacketInfo, PortManager, TcpPortManager, IcmpEchoPortManager};
use std::{marker::PhantomData, net::Ipv4Addr};
use pnet::packet::{Packet, tcp::TcpPacket, ipv4::MutableIpv4Packet, MutablePacket};
use slotmap::DefaultKey;
use std::fmt::Display;
use std::hash::Hash;
pub trait NATter{
    fn transform<'a>(&mut self, p:MutableIpv4Packet<'a>, ingress: bool) -> Option<MutableIpv4Packet<'a>>;
    fn transform_icmp<'a>(&mut self, p:MutableIpv4Packet<'a>) -> Option<MutableIpv4Packet<'a>>;
    fn print_status(&self);
}
pub struct HashNATTer<P: PortManager, N:NATter0<P>>{
    pub p: PhantomData<P>,
    pub global_addr: Ipv4Addr,
    pub table: N
}
impl<P:PortManager, N:NATter0<P>> NATter for HashNATTer<P, N>{
    fn print_status(&self){self.table.print_status0()}
    fn transform<'a>(&mut self, pkt1:MutableIpv4Packet<'a>, ingress: bool) -> Option<MutableIpv4Packet<'a>>{
        self.table.transform(pkt1,ingress, self.global_addr)
    }
    fn transform_icmp<'a>(&mut self, mut packet: MutableIpv4Packet<'a>) -> Option<MutableIpv4Packet<'a>>  {
        let p = packet.payload_mut();
        let l4_payload = 8 + 4*(p.get(8)?%16) as usize;//8 is ICMP error header, the rest is IP header inside ICMP error
        //note that src/dst is kind of "reversed"
        if p.len() < l4_payload+4 {return None};
        let sport_u16 = ((p[l4_payload+0] as u16) << 8) + p[l4_payload+1] as u16;
        let dport_u16 = ((p[l4_payload+2] as u16) << 8) + p[l4_payload+3] as u16;
        //let saddr_obj = Ipv4Addr::new(p[20], p[21], p[22], p[23]);
        let daddr_obj = Ipv4Addr::new(p[24], p[25], p[26], p[27]);

        match self.table.transform_icmp_error(sport_u16, daddr_obj, dport_u16){
            Some((addr, port)) => {
                let [a0, a1, a2, a3] = addr.octets();
                p[20] =a0; p[21] =a1; p[22] =a2; p[23] =a3;
                let lp = port;
                p[l4_payload+0] = (lp >>8) as u8;
                p[l4_payload+1] = lp as u8 & 0xFF;
                //rewrite dest addr
                [*packet.packet_mut().get_mut(16)?, *packet.packet_mut().get_mut(17)?, *packet.packet_mut().get_mut(18)?, *packet.packet_mut().get_mut(19)?] = addr.octets();
                IcmpEchoPortManager::correct_checksum(packet)},
            None => {
                //self.write_log(format!("[{}]{} ICMP_ingress_not_found: {}:{} -> {}:{}\n", self.name, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(), daddr_obj, dport_u16, saddr_obj, sport_u16)); 
            None}
        }
    }
}

pub trait NATter0<P>{
    fn print_status0(&self);
    fn transform<'a>(&mut self, pkt1:MutableIpv4Packet<'a>, ingress: bool, global_addr: Ipv4Addr) -> Option<MutableIpv4Packet<'a>>;
    fn transform_icmp_error(&mut self, local_port: u16, remote_addr: Ipv4Addr, remote_port: u16) -> Option<(Ipv4Addr,u16)> ;
}

impl <LK:Display+Copy+Eq+Hash, C: KeyGen<LK, DefaultKey>> NATter0<TcpPortManager> for TcpStateHashNATTable<LK, C>{
    fn print_status0(&self){self.print_status()}
    fn transform<'a>(&mut self, mut pkt1:MutableIpv4Packet<'a>, ingress: bool, global_addr: Ipv4Addr) -> Option<MutableIpv4Packet<'a>> {
        let pi: PacketInfo = TcpPortManager::get_info(&pkt1.to_immutable());
        let newp = if ingress{
            let (a, p) =self.my_transform_ingress(pi, TcpPacket::new(pkt1.payload()).unwrap().get_flags())?; 
            pkt1.set_destination(a);
            TcpPortManager::set_dst_port(pkt1, p)? 
        } else {
            let np = self.my_transform_egress(pi, TcpPacket::new(pkt1.payload()).unwrap().get_flags())?;
            pkt1.set_source(global_addr);
            TcpPortManager::set_src_port(pkt1, np)?
        };
        TcpPortManager::correct_checksum(newp)
    }
    fn transform_icmp_error(&mut self, local_port: u16, remote_addr: Ipv4Addr, remote_port: u16) -> Option<(Ipv4Addr,u16)>{
        self.my_transform_icmp_error(local_port,remote_addr,remote_port )
    }
}

impl <P:PortManager, LK:Display+Copy+Eq+Hash, C: KeyGen<LK, DefaultKey>> NATter0<P> for HashNATTable<LK, C>{
    fn print_status0(&self){self.print_status()}
    fn transform<'a>(&mut self, mut pkt1:MutableIpv4Packet<'a>, ingress: bool, global_addr: Ipv4Addr) -> Option<MutableIpv4Packet<'a>>{
        let pi: PacketInfo = P::get_info(&pkt1.to_immutable());
        let newp = if ingress{
            let (a, p) =self.my_transform_ingress(pi)?;
            pkt1.set_destination(a);
            P::set_dst_port(pkt1, p)?} else {
                let np = self.my_transform_egress(pi)?;
            pkt1.set_source(global_addr);
            P::set_src_port(pkt1, np)?
        };
        P::correct_checksum(newp)
    }
    fn transform_icmp_error(&mut self, local_port: u16, remote_addr: Ipv4Addr, remote_port: u16) -> Option<(Ipv4Addr,u16)>{
        self.my_transform_icmp_error(local_port,remote_addr,remote_port )
    }
}