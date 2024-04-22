
use std::fmt::{Display, Formatter, Result};
use std::collections::HashMap;
use std::net::Ipv4Addr;

use rand::{Rng, rngs::ThreadRng, thread_rng};

#[derive(Eq, Hash, PartialEq, Copy, Clone)]
pub struct AddrPort(Ipv4Addr, u16);

#[derive(Eq, Hash, PartialEq, Copy, Clone)]
pub struct MyUnit();

#[derive(Eq, Hash, PartialEq, Copy, Clone)]
pub struct MyAddr(Ipv4Addr);

impl Display for AddrPort{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}
impl AddrPort{
    pub fn from_t(tuple: (Ipv4Addr, u16))->Self{Self(tuple.0, tuple.1)}
}

impl Display for MyUnit{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "*:*")
    }
}
impl Display for MyAddr{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}:*",self.0)
    }
}


#[derive(Eq, Hash, PartialEq)]
pub struct LI<T> {
    pub local_tuple: (Ipv4Addr, u16),
    pub lk: T
}
#[derive(Eq, Hash, PartialEq)]
pub struct RI<T>{
    pub global_port: u16,
    pub nat_key: T 
}
pub trait KeyGen<LK, T> {
    fn local_key_from_tuple(&self, remote_tuple: (Ipv4Addr,  u16)) -> LK;
    fn empty_port(&mut self, remotes: &HashMap<RI<LK>, T>, remote_tuple: (Ipv4Addr,  u16), local_port: u16, last_assigned: Option<&u16>) -> Option<u16>;
}

pub struct SymmetricNATTable{
    rng : ThreadRng,
    global_ports : Vec<u16>
}

impl SymmetricNATTable{
    pub fn new(global_ports: Vec<u16>) -> Self{
        Self {rng: thread_rng(), global_ports: global_ports }
    }
}

impl <T> KeyGen<AddrPort, T> for SymmetricNATTable {//(saddr, sport, daddr, dport) and (dport, saddr, sport)
    fn local_key_from_tuple(&self, remote_tuple: (Ipv4Addr,  u16)) -> AddrPort {
        AddrPort::from_t(remote_tuple)
    }
    fn empty_port(&mut self, remotes: &HashMap<RI<AddrPort>, T>, remote_tuple: (Ipv4Addr,  u16), _local_port: u16, _last_assigned: Option<&u16>) -> Option<u16> {
        for _ in 1..20 {
            let test_port = self.global_ports[self.rng.gen::<usize>() % self.global_ports.len()];
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<SymmetricNATTable as KeyGen<AddrPort, T>>::local_key_from_tuple(self, remote_tuple)}){
                return Some(test_port)
            }
        }
        None
    }
}

pub struct FullConeNATTable{
    rng : ThreadRng,
    global_ports : Vec<u16>
}
impl FullConeNATTable{
    pub fn new(global_ports: Vec<u16>) -> Self{
        Self {rng: thread_rng(), global_ports: global_ports }
    }
}

impl <T> KeyGen<MyUnit, T> for FullConeNATTable{//(saddr, sport, daddr, dport) and (dport, saddr, sport)
    fn local_key_from_tuple(&self, _remote_tuple: (Ipv4Addr,  u16)) -> MyUnit {
        MyUnit()
    }
    fn empty_port(&mut self, remotes: &HashMap<RI<MyUnit>, T>, remote_tuple: (Ipv4Addr,  u16), _local_port: u16, _last_assigned: Option<&u16>) -> Option<u16> {
        for _ in 1..20 {
            let test_port = self.global_ports[self.rng.gen::<usize>() % self.global_ports.len()];
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<FullConeNATTable as KeyGen<MyUnit, T>>::local_key_from_tuple(self, remote_tuple)}){
                return Some(test_port)
            }
        }
        None
    }
}

pub struct RestrictedConeNATTable{
    rng : ThreadRng,
    global_ports : Vec<u16>
}
impl RestrictedConeNATTable{
    pub fn new(global_ports: Vec<u16>) -> Self{
        Self {rng: thread_rng(), global_ports: global_ports }
    }
}

impl <T> KeyGen<MyAddr, T> for RestrictedConeNATTable{//(saddr, sport, daddr, dport) and (dport, saddr, sport)
    fn local_key_from_tuple(&self, remote_tuple: (Ipv4Addr,  u16)) -> MyAddr  {
        MyAddr(remote_tuple.0)
    }
    fn empty_port(&mut self, remotes: &HashMap<RI<MyAddr>, T>, remote_tuple: (Ipv4Addr,  u16), _local_port: u16, last_assigned: Option<&u16>) -> Option<u16> {
        if let Some(&test_port) = last_assigned{
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<RestrictedConeNATTable as KeyGen<MyAddr, T>>::local_key_from_tuple(self, remote_tuple)}){
                return Some(test_port)
            }
        }
        for _ in 1..20 {
            let test_port = self.global_ports[self.rng.gen::<usize>() % self.global_ports.len()];
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<RestrictedConeNATTable as KeyGen<MyAddr, T>>::local_key_from_tuple(self, remote_tuple)}){
                return Some(test_port)
            }
        }
        None
    }
}
