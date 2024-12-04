
use std::fmt::{Display, Formatter, Result};
use std::collections::HashMap;
use std::net::Ipv4Addr;

use rand::{Rng, rngs::ThreadRng, thread_rng};

#[derive(Eq, Hash, PartialEq, Copy, Clone)]
pub struct MyAddrPort(Ipv4Addr, u16);

#[derive(Eq, Hash, PartialEq, Copy, Clone)]
pub struct MyUnit();

#[derive(Eq, Hash, PartialEq, Copy, Clone)]
pub struct MyAddr(Ipv4Addr);

impl Display for MyAddrPort{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}:{}", self.0, self.1)
    }
}
impl MyAddrPort{
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

//(for egress) data structure to specify a NAT entry by local-side information
#[derive(Eq, Hash, PartialEq)]
pub struct LI<T> {
    pub local_tuple: (Ipv4Addr, u16),
    pub lk: T
}

//(for ingress) data structure to specify a NAT entry by remote-side information
#[derive(Eq, Hash, PartialEq)]
pub struct RI<T>{
    pub global_port: u16,
    pub nat_key: T 
}
pub trait KeyGen<LK, T> {
    //create nat key from remote tuple
    fn local_key_from_tuple(&self, remote_tuple: (Ipv4Addr,  u16)) -> LK;
    // local tuple is only used in strict ADM/APDM
    fn empty_port(&mut self, locals_used_port: &mut HashMap<(Ipv4Addr, u16, u16), MyUnit>, remotes: &HashMap<RI<LK>, T>, remote_tuple: (Ipv4Addr,  u16), local_tuple: (Ipv4Addr,  u16), last_assigned: Option<&u16>) -> Option<u16>;
}

pub struct QuasiSymmetric{
    rng : ThreadRng,
    global_ports : Vec<u16>
}

impl QuasiSymmetric{
    pub fn new(global_ports: Vec<u16>) -> Self{
        Self {rng: thread_rng(), global_ports: global_ports }
    }
}

impl <T> KeyGen<MyAddrPort, T> for QuasiSymmetric {
    fn local_key_from_tuple(&self, remote_tuple: (Ipv4Addr,  u16)) -> MyAddrPort {
        MyAddrPort::from_t(remote_tuple)
    }
    fn empty_port(&mut self, _locals_used_port: &mut HashMap<(Ipv4Addr, u16, u16), MyUnit>, remotes: &HashMap<RI<MyAddrPort>, T>, remote_tuple: (Ipv4Addr,  u16), _local_tuple: (Ipv4Addr,  u16), _last_assigned: Option<&u16>) -> Option<u16> {
        for _ in 1..20 {
            let test_port = self.global_ports[self.rng.gen::<usize>() % self.global_ports.len()];
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<QuasiSymmetric as KeyGen<MyAddrPort, T>>::local_key_from_tuple(self, remote_tuple)}){
                return Some(test_port)
            }
        }
        None
    }
}

pub struct FullCone{
    rng : ThreadRng,
    global_ports : Vec<u16>
}
impl FullCone{
    pub fn new(global_ports: Vec<u16>) -> Self{
        Self {rng: thread_rng(), global_ports: global_ports }
    }
}

impl <T> KeyGen<MyUnit, T> for FullCone{
    fn local_key_from_tuple(&self, _remote_tuple: (Ipv4Addr,  u16)) -> MyUnit {
        MyUnit()
    }
    fn empty_port(&mut self, _locals_used_port: &mut HashMap<(Ipv4Addr, u16, u16), MyUnit>, remotes: &HashMap<RI<MyUnit>, T>, remote_tuple: (Ipv4Addr,  u16), _local_tuple: (Ipv4Addr,  u16), _last_assigned: Option<&u16>) -> Option<u16> {
        for _ in 1..20 {
            let test_port = self.global_ports[self.rng.gen::<usize>() % self.global_ports.len()];
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<FullCone as KeyGen<MyUnit, T>>::local_key_from_tuple(self, remote_tuple)}){
                return Some(test_port)
            }
        }
        None
    }
}

pub struct QuasiRestrictedCone{
    rng : ThreadRng,
    global_ports : Vec<u16>
}
impl QuasiRestrictedCone{
    pub fn new(global_ports: Vec<u16>) -> Self{
        Self {rng: thread_rng(), global_ports: global_ports }
    }
}

impl <T> KeyGen<MyAddr, T> for QuasiRestrictedCone{
    fn local_key_from_tuple(&self, remote_tuple: (Ipv4Addr,  u16)) -> MyAddr  {
        MyAddr(remote_tuple.0)
    }
    fn empty_port(&mut self, _locals_used_port: &mut HashMap<(Ipv4Addr, u16, u16), MyUnit>, remotes: &HashMap<RI<MyAddr>, T>, remote_tuple: (Ipv4Addr,  u16), _local_tuple: (Ipv4Addr,  u16), last_assigned: Option<&u16>) -> Option<u16> {
        if let Some(&test_port) = last_assigned{
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<QuasiRestrictedCone as KeyGen<MyAddr, T>>::local_key_from_tuple(self, remote_tuple)}){
                return Some(test_port)
            }
        }
        for _ in 1..20 {
            let test_port = self.global_ports[self.rng.gen::<usize>() % self.global_ports.len()];
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<QuasiRestrictedCone as KeyGen<MyAddr, T>>::local_key_from_tuple(self, remote_tuple)}){
                return Some(test_port)
            }
        }
        None
    }
}

pub struct QuasiPortRestrictedCone{//mixture of QuasiRestrictedCone and QuasiSymmetric
    rng : ThreadRng,
    global_ports : Vec<u16>
}
impl QuasiPortRestrictedCone{
    pub fn new(global_ports: Vec<u16>) -> Self{
        Self {rng: thread_rng(), global_ports: global_ports }
    }
}

impl <T> KeyGen<MyAddrPort, T> for QuasiPortRestrictedCone{
    fn local_key_from_tuple(&self, remote_tuple: (Ipv4Addr,  u16)) -> MyAddrPort  {
        MyAddrPort::from_t(remote_tuple)
    }
    fn empty_port(&mut self, _locals_used_port: &mut HashMap<(Ipv4Addr, u16, u16), MyUnit>, remotes: &HashMap<RI<MyAddrPort>, T>, remote_tuple: (Ipv4Addr,  u16), _local_tuple: (Ipv4Addr,  u16), last_assigned: Option<&u16>) -> Option<u16> {
        if let Some(&test_port) = last_assigned{
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<QuasiPortRestrictedCone as KeyGen<MyAddrPort, T>>::local_key_from_tuple(self, remote_tuple)}){
                return Some(test_port)
            }
        }
        for _ in 1..20 {
            let test_port = self.global_ports[self.rng.gen::<usize>() % self.global_ports.len()];
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<QuasiPortRestrictedCone as KeyGen<MyAddrPort, T>>::local_key_from_tuple(self, remote_tuple)}){
                return Some(test_port)
            }
        }
        None
    }
}

//AddressDependent and AddressPortDependent are strict ADM/APDM implementation

//ADM&ADF, port increment
pub struct AddressDependent{
    rng : ThreadRng,
    global_ports : Vec<u16>,
    get_next_port: fn(u16) -> u16
}
impl AddressDependent{
    pub fn new(global_ports: Vec<u16>, get_next_port: fn(u16) -> u16) -> Self{
        Self {rng: thread_rng(), global_ports: global_ports, get_next_port}
    }
}
impl <T> KeyGen<MyAddr, T> for AddressDependent{
    fn local_key_from_tuple(&self, remote_tuple: (Ipv4Addr,  u16)) -> MyAddr  {
        MyAddr(remote_tuple.0)
    }
    fn empty_port(&mut self, locals_used_port: &mut HashMap<(Ipv4Addr, u16, u16), MyUnit>, remotes: &HashMap<RI<MyAddr>, T>, remote_tuple: (Ipv4Addr,  u16), local_tuple: (Ipv4Addr,  u16), last_assigned: Option<&u16>) -> Option<u16> {
        if let Some(&test_port0) = last_assigned{
            let test_port = (self.get_next_port)(test_port0);
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<AddressDependent as KeyGen<MyAddr, T>>::local_key_from_tuple(self, remote_tuple)}){
                if let None = locals_used_port.get(&(local_tuple.0, local_tuple.1, test_port)){
                    locals_used_port.insert((local_tuple.0, local_tuple.1, test_port), MyUnit());
                    return Some(test_port)
                }
            }
        }
        for _ in 1..20 {
            let test_port = self.global_ports[self.rng.gen::<usize>() % self.global_ports.len()];
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<AddressDependent as KeyGen<MyAddr, T>>::local_key_from_tuple(self, remote_tuple)}){
                if let None = locals_used_port.get(&(local_tuple.0, local_tuple.1, test_port)){
                    locals_used_port.insert((local_tuple.0, local_tuple.1, test_port), MyUnit());
                    return Some(test_port)
                }
            }
        }
        None
    }
}
//APDM&APDF, port increment
pub struct AddressPortDependent{
    rng : ThreadRng,
    global_ports : Vec<u16>,
    get_next_port: fn(u16) -> u16
}
impl AddressPortDependent{
    pub fn new(global_ports: Vec<u16>, get_next_port: fn(u16) -> u16) -> Self{
        Self {rng: thread_rng(), global_ports: global_ports, get_next_port}
    }
}

impl <T> KeyGen<MyAddrPort, T> for AddressPortDependent{
    fn local_key_from_tuple(&self, remote_tuple: (Ipv4Addr,  u16)) -> MyAddrPort  {
        MyAddrPort::from_t(remote_tuple)
    }
    //We easily implement "Quasi-ADM APDM NAT" if we use "ADM guard" here
    fn empty_port(&mut self, locals_used_port: &mut HashMap<(Ipv4Addr, u16, u16), MyUnit>, remotes: &HashMap<RI<MyAddrPort>, T>, remote_tuple: (Ipv4Addr,  u16), local_tuple: (Ipv4Addr,  u16), last_assigned: Option<&u16>) -> Option<u16> {
        if let Some(&test_port0) = last_assigned{
            let test_port = (self.get_next_port)(test_port0);
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<AddressPortDependent as KeyGen<MyAddrPort, T>>::local_key_from_tuple(self, remote_tuple)}){
                if let None = locals_used_port.get(&(local_tuple.0, local_tuple.1, test_port)){
                    locals_used_port.insert((local_tuple.0, local_tuple.1, test_port), MyUnit());
                    return Some(test_port)
                }
            }
        }
        for _ in 1..20 {
            let test_port = self.global_ports[self.rng.gen::<usize>() % self.global_ports.len()];
            if let None = remotes.get(&RI{global_port: test_port, nat_key:<AddressPortDependent as KeyGen<MyAddrPort, T>>::local_key_from_tuple(self, remote_tuple)}){
                if let None = locals_used_port.get(&(local_tuple.0, local_tuple.1, test_port)){
                    locals_used_port.insert((local_tuple.0, local_tuple.1, test_port), MyUnit());
                    return Some(test_port)
                }
            }
        }
        None
    }
}

