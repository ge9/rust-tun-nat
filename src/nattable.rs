
use crate::keygen::{MyAddrPort, MyUnit, LI, RI};
use crate::util::{PacketInfo, NatEntry};
use crate::ll::{LLIter, LList};
use crate::keygen::KeyGen;

use std::{fmt::Display, hash::Hash, sync::Arc, collections::HashMap, net::Ipv4Addr, time::{SystemTime, UNIX_EPOCH}};
use slotmap::DefaultKey;
use tokio::{io::AsyncWriteExt, sync::Mutex};

use chrono::prelude::*;

//Dual HashMap structure to manage port usage. locals and remotes are used for egress and ingress lookup respectively.
pub struct RLHash<LK:Copy+Eq+Hash, C: KeyGen<LK, DefaultKey>>{
    locals: HashMap<LI<LK>, DefaultKey>,
    //the last-assigned port for the local tuple. 
    //If we want "Quasi-ADM APDM NAT", it's better if we can get each last-assigned port per local tuple *and remote address*, but that's not currently implemented?
    //(maybe it's sufficient to try the last assigned port but check locals_used_port to decide if it's already used for another remote address)
    //TODO: add expiry to avoid massive memory consumption
    locals_last_assigned: HashMap<(Ipv4Addr, u16), u16>,
    //Register tuple `(local address, local port, global port)` to implement strict ADM/APDM NAT behavior. (not used in QuasiXXX tables)
    //If we want "Quasi-ADM APDM NAT" (i.e. MUST not use same global port for different remote *addresses* but MAY use same global port for different *ports* of a single remote address), 
    //we should use Ipv4Addr instead of MyUnit to decide the remote address for which the tuple is used.
    locals_used_port: HashMap<(Ipv4Addr, u16, u16), MyUnit>,
    remotes: HashMap<RI<LK>, DefaultKey>,
    keygen: C
}
impl<LK:Display+Copy+Eq+Hash, C: KeyGen<LK, DefaultKey>> RLHash<LK, C> {
    pub fn new(keygen: C) -> Self{
        Self {
            keygen: keygen,
            locals : HashMap::new(),
            locals_last_assigned : HashMap::new(),
            locals_used_port : HashMap::new(),
            remotes : HashMap::new(),
        }
    }
    pub fn get_local(&self, local_key: &LI<LK>) -> Option<&DefaultKey>{
        self.locals.get(local_key)
    }
    pub fn get_remote(&self, remote_key: RI<LK>) -> Option<&DefaultKey>{
        self.remotes.get(&remote_key)
    }
    pub fn get_lk(&self, remote_tuple: (Ipv4Addr, u16)) -> LK{
        self.keygen.local_key_from_tuple( remote_tuple)
    }
    //or can we use "vacantentry" mechanism to implement "try_assign_port" function? 
    pub fn get_empty_port(&mut self, p:&PacketInfo) -> Option<u16>{
        let last_assigned = self.locals_last_assigned.get(&p.src_tuple);
        self.keygen.empty_port(&mut self.locals_used_port, &self.remotes, p.dst_tuple, p.src_tuple, last_assigned)
    }
    pub fn insert(&mut self, k: DefaultKey,  local_tuple: (Ipv4Addr, u16), global_port: u16, lk: LK){
        self.locals_last_assigned.insert(local_tuple, global_port);
        self.locals.insert(LI{local_tuple:local_tuple, lk: lk}, k);
        self.remotes.insert(RI{global_port:global_port, nat_key:lk}, k);
    }
    pub fn remove(&mut self,  local_tuple: (Ipv4Addr, u16), global_port: u16, lk: LK){
        self.locals.remove(&LI{local_tuple:local_tuple, lk: lk});
        self.remotes.remove(&RI{global_port:global_port, nat_key:lk});
        self.locals_used_port.remove(&(local_tuple.0, local_tuple.1, global_port));
    }
}
pub struct HashNATTable<LK:Copy+Eq+Hash, C: KeyGen<LK, DefaultKey>> {
    logfile: Arc<Mutex<tokio::fs::File>>,
    idle_timeout: u64,
    name: String,
    entrylist: LList<NatEntry<LK>>,
    rlhash:  RLHash<LK, C>
}
//generate local keys and remote keys. 1-to-1 correspondence [between LK and NatEntry] and [between RK and NatEntry]
//for ordinary EIM/ADF and EIM/APDF behavior, we may need "remote mapping key" and "remote filter key", and more complex NatEntry data
impl<LK:Display+Copy+Eq+Hash, C: KeyGen<LK, DefaultKey>> HashNATTable<LK, C> {
    pub fn new(name: String, idle_timeout: u64, keygen: C, logfile: Arc<Mutex<tokio::fs::File>>) -> Self{
        Self {
            logfile: logfile,
            name: name,
            idle_timeout: idle_timeout,
            entrylist: LList::new(),//no entry at first
            rlhash: RLHash::new(keygen)
        }
    }
    fn write_log(&self, s:String){
        let lf = Arc::clone(&self.logfile);
        tokio::task::spawn(async move {
            let mut f = lf.lock().await;
            f.write_all(s.as_bytes()).await.expect("write failed");
        });
    }
    pub fn print_status(&self){
        println!("***************{}***************",self.name);
        for (e,_k) in LLIter(&self.entrylist, self.entrylist.head()){
            let datetime = DateTime::from_timestamp((e.last_egress+self.idle_timeout) as i64, 0).unwrap();
            // Format the datetime how you want
            let newdate = datetime.format("%Y-%m-%d %H:%M:%S");
            println!("{}[{}]{}->{}",newdate, e.global_port, MyAddrPort::from_t(e.local_tuple), e.nat_key)
        }
    }
    pub fn my_transform_egress<'a>(&'a mut self, p: PacketInfo) -> Option<u16> {
        let now: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let local_key = self.rlhash.get_lk(p.dst_tuple);
        let li = LI{local_tuple: p.src_tuple, lk: local_key};
        //we could check whether the entry has expired, but that's not necessary
        if let Some(entry) = self.rlhash.get_local(&li) {
            let mut d = self.entrylist.move_to_tail_and_get(*entry);
            d.last_egress = now;
            Some(Self::egress(p, &mut d))
        } else {
            self.gc(now);
            let global_port = self.rlhash.get_empty_port(&p);
            match global_port {
                Some(port) => {
                    self._insert_and_egress(now, p, port, li.lk)
                }
                None => {
                    self.write_log(format!("[{}]{} no_empty_port: {} -> {}\n", self.name, now, MyAddrPort::from_t(p.src_tuple), li.lk));
                    None
                }
            }
        }
    }
    fn egress<'a>(p: PacketInfo, entry:&mut NatEntry<LK>) -> u16 {
        entry.packets_sent += 1;
        entry.bytes_sent += p.size as u32;
        entry.global_port
    }
    pub fn my_transform_ingress<'a>(&mut self, p: PacketInfo) -> Option<(Ipv4Addr, u16)> {
        let remote_key = self.rlhash.get_lk( p.src_tuple);
        match self.rlhash.get_remote(RI{global_port:p.dst_tuple.1, nat_key: remote_key}){
            Some(entry) => {Self::ingress(p, &mut self.entrylist.get_mut(*entry).unwrap())},
            None => {self.write_log(format!("[{}]{} ingress_not_found: via {} from {}\n", self.name, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            p.dst_tuple.1, MyAddrPort::from_t(p.src_tuple))); None}
        }
    }
    fn ingress<'a>(p: PacketInfo, entry:&mut NatEntry<LK>) -> Option<(Ipv4Addr, u16)> {
        entry.packets_received += 1;
        entry.bytes_received += p.size as u32;
        return Some(entry.local_tuple)
    }
    pub fn my_transform_icmp_error(&mut self, local_port: u16, remote_addr: Ipv4Addr, remote_port: u16) -> Option<(Ipv4Addr,u16)> {
        let remote_key = self.rlhash.get_lk((remote_addr, remote_port));
        match self.rlhash.get_remote(RI{global_port: local_port, nat_key: remote_key}){
            Some(&entry) => {
                let e = self.entrylist.get(entry).unwrap();
                return Some(e.local_tuple)},
            None => {None}
        }
    }
    fn gc(&mut self, now: u64){
        let items_before = now - self.idle_timeout;
        loop{
            if let Some(head) = self.entrylist.get(self.entrylist.head()){
                if head.last_egress >= items_before {return}
                let mut t = self.entrylist.pop_head().unwrap();
                self._gc_head_entry(&mut t, now);
            }else{return}
        }
    }
    fn _gc_head_entry(&mut self, entry: &NatEntry<LK>, t: u64) {
        self.write_log(format!("[{}]{} removing: via {}: {} -> {}\n", self.name, t, entry.global_port, MyAddrPort::from_t(entry.local_tuple), entry.nat_key));
        self.rlhash.remove(entry.local_tuple, entry.global_port,entry.nat_key)
    }
    fn _insert_and_egress<'a>(&mut self, now: u64, p: PacketInfo, global_port: u16, lk:LK) ->  Option<u16> {
        let entry = NatEntry::new(now, lk, p.src_tuple, global_port);
        let k = self.entrylist.push_tail(entry);
        self.rlhash.insert(k,  p.src_tuple, global_port, lk);
        self.write_log(format!("[{}]{} inserting: via {}: {} -> {}\n", self.name, now, global_port, MyAddrPort::from_t(p.src_tuple), lk));
        let mut e =  self.entrylist.get_mut(k).unwrap();
        Some(Self::egress(p, &mut e))
    }
}
