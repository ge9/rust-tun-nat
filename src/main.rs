use crate::nat::{NATter, HashNATTer};
use crate::statenattable::TcpStateHashNATTable;
use crate::nattable::HashNATTable;
use crate::keygen::{FullCone, QuasiRestrictedCone, QuasiSymmetric, QuasiPortRestrictedCone, AddressDependent, AddressPortDependent};
use crate::util::{TcpPortManager, UdpPortManager, IcmpEchoPortManager};
use crate::util::port_range;

use std::sync::Arc;
use tokio::{sync::Mutex, fs::OpenOptions};
use futures::{SinkExt, StreamExt};
use pnet::packet::{ip::IpNextHeaderProtocols, icmp::{IcmpPacket, IcmpTypes}, ipv4, Packet};
use tun::{self, TunPacket};

mod tcpstate;
mod statenattable;
mod util;
mod nattable;
mod nat;
mod keygen;
mod ll;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>{

    let mut config = tun::Configuration::default();

    config
    //    .address((10, 0, 0, 1))
    //    .netmask((255, 255, 255, 0))
        .name("rustnat")
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|config| {
        config.packet_information(true);
    });
    let dev = tun::create_as_async(&config).unwrap();
    let mut framed = dev.into_framed();

    let file = OpenOptions::new().read(true).append(true).open("rustnat.log").await?;
    let reffile = Arc::new(Mutex::new(file));

    let global_addr = std::net::Ipv4Addr::new(192, 168, 0, 135);
    //let port_range= port_range::gen_v6plus(33);
    let port_range: Vec<u16>= (19900..20000).collect();//100 ports
    let tcp_table = TcpStateHashNATTable::new(String::from("tcp"), 2000, 120, QuasiRestrictedCone::new(port_range.clone()),Arc::clone(&reffile));
    let udp_table = HashNATTable::new(String::from("udp"), 150, AddressPortDependent::new(port_range.clone(), get_next_port),Arc::clone(&reffile));
    let icmp_echo_table= HashNATTable::new(String::from("icmp-echo"), 150,QuasiSymmetric::new(port_range.clone()),Arc::clone(&reffile));
    let mut tcpn = HashNATTer{table:tcp_table, global_addr: global_addr, p: core::marker::PhantomData::<TcpPortManager>};
    let mut udpn = HashNATTer{table:udp_table, global_addr: global_addr, p: core::marker::PhantomData::<UdpPortManager>};
    let mut icmpn = HashNATTer{table:icmp_echo_table, global_addr: global_addr, p: core::marker::PhantomData::<IcmpEchoPortManager>};
    while let Some(packet) = framed.next().await {
        let pkt0 = packet?;
        if pkt0.get_bytes()[0]/16 == 4 {//v4
            match ipv4::MutableIpv4Packet::new(pkt0.get_bytes().to_vec().as_mut_slice()) {
                Some(pkt1) => {
                    if pkt1.get_destination() == std::net::Ipv4Addr::new(192, 0, 2, 2){tcpn.print_status();udpn.print_status();icmpn.print_status();continue}
                    let ingress = pkt1.get_destination() == global_addr;
                    let pkt2 = match pkt1.get_next_level_protocol(){
                        IpNextHeaderProtocols::Tcp => {tcpn.transform(pkt1, ingress)},
                        IpNextHeaderProtocols::Udp => {udpn.transform(pkt1, ingress)},
                        IpNextHeaderProtocols::Icmp => {if let Some(icmp) =IcmpPacket::new(pkt1.payload()){
                            match icmp.get_icmp_type() {
                                IcmpTypes::EchoRequest => if !ingress {icmpn.transform(pkt1, false)} else {None},
                                IcmpTypes::EchoReply => if ingress {icmpn.transform(pkt1, true)} else {None},
                                IcmpTypes::DestinationUnreachable | IcmpTypes::TimeExceeded=> {
                                    let p = icmp.payload();
                                    match p.get(13){//original protocol number
                                        Some(17) => udpn.transform_icmp(pkt1),//UDP
                                        Some(6) =>  tcpn.transform_icmp(pkt1),//TCP
                                        _ => None
                                    }
                                },
                                _ => None
                            }
                        }else{None} },
                        _ => None
                    };
                    if let Some(mut natted) = pkt2{
                        natted.set_checksum(ipv4::checksum(&natted.to_immutable()));
                        framed.send(TunPacket::new(natted.packet().to_vec())).await?;
                    }
                }
                None => println!("Received an invalid packet"),
            }
        }else{//v6
        }
    }
    Ok(())

}

fn get_next_port(x: u16) -> u16 {
    ((x-19900+1) % 100) + 19900
}