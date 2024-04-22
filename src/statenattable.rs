
use chrono::DateTime;
use crate::ll::{LLIter, LList};
use crate::keygen::{AddrPort, RI, LI};
use crate::nattable::RLHash;
use crate::util::{PacketInfo, NatEntry};
use crate::tcpstate::{TcpStateMachine, TcpState};
use crate::keygen::KeyGen;

use std::{fmt::Display, hash::Hash, sync::Arc, collections::HashMap, net::Ipv4Addr, time::{SystemTime, UNIX_EPOCH}};
use slotmap::{DefaultKey, Key, SlotMap};
use tokio::{io::AsyncWriteExt, sync::Mutex};

pub struct ConnInfo{
    state_m: TcpStateMachine,
    will_expire: u64,
    belongs_to: DefaultKey,
    remote_tuple:(Ipv4Addr, u16)
}

pub struct TcpStateHashNATTable<LK:Display+Copy+Eq+Hash, C: KeyGen<LK, DefaultKey>> {
    logfile: Arc<Mutex<tokio::fs::File>>,
    idle_timeout_long: u64,
    idle_timeout_short: u64,
    name: String,
    //entry and counter
    entrylist: SlotMap<DefaultKey, (NatEntry<LK>, u16)>,
    connlist: LList<ConnInfo>,
    connhash: HashMap<(u16, (Ipv4Addr, u16)), DefaultKey>,
    //A "marker" that indicates short_timeout.  Concretely, the connection with shortest remaining life in those who will live longer than last GC time+short_timeout (if none, Defaultkey::null)
    conn_least_longer_than_short_timeout: DefaultKey,
    rlhash: RLHash<LK, C>
}

impl<LK:Display+Copy+Eq+Hash, C: KeyGen<LK, DefaultKey>> TcpStateHashNATTable<LK, C> {
    pub fn new(name: String, idle_timeout_long: u64, idle_timeout_short: u64, keygen: C, logfile: Arc<Mutex<tokio::fs::File>>) -> Self{
        Self {
            logfile: logfile,
            name: name,
            idle_timeout_long: idle_timeout_long,
            idle_timeout_short: idle_timeout_short,
            rlhash: RLHash::new(keygen),
            entrylist: SlotMap::new(),
            conn_least_longer_than_short_timeout: DefaultKey::null(),
            connhash: HashMap::new(),
            connlist: LList::new(),
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
        let mut ord = Vec::new();
        let mut hs = HashMap::new();
        
        for (e,_k) in LLIter(&self.connlist, self.connlist.head()){
            if !hs.contains_key(&e.belongs_to){
                ord.push(e.belongs_to);
                hs.insert(e.belongs_to, Vec::new());
            }
        }
        for (e,&k) in self.connhash.iter(){
            let ci=self.connlist.get(k).unwrap();
            hs.get_mut(&ci.belongs_to).unwrap().push((e,ci));
        }
        for k in ord{
            let ent = &self.entrylist[k];
            println!("{}[{}]{}->{}", ent.1, ent.0.global_port, AddrPort::from_t(ent.0.local_tuple), ent.0.nat_key);
            for en in hs.get(&k).unwrap(){
                let datetime = DateTime::from_timestamp(en.1.will_expire as i64, 0).unwrap();
                let newdate = datetime.format("%Y-%m-%d %H:%M:%S");
                println!("  {}[{:?}]{}", newdate, en.1.state_m.state, AddrPort::from_t(en.0.1));
            }
        }
        // for (e,k) in LLIter(&self.connlist, self.connlist.head()){
        //     if k == self.conn_least_longer_than_short_timeout{println!("--------------")}
        //     let datetime = DateTime::from_timestamp(e.will_expire as i64, 0).unwrap();
        //     let parent = self.entrylist.get(e.belongs_to).unwrap();
        //     let newdate = datetime.format("%Y-%m-%d %H:%M:%S");
        //     println!("{}[{}]{}",newdate,parent.0.global_port, AddrPort::from_t(parent.0.local_tuple))
        // }
    }
    pub fn my_transform_egress<'a>(&'a mut self, p: PacketInfo, flags: u8) -> Option<u16> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let local_key = self.rlhash.get_lk(p.dst_tuple);
        let li = LI{local_tuple: p.src_tuple, lk: local_key};
        if let Some(&entry_key) = self.rlhash.get_local(&li) {
            self.entrylist[entry_key].0.last_egress = now;
            let conntuple = (self.entrylist[entry_key].0.global_port, p.dst_tuple);
            self.update_connstate(false, conntuple, flags, now, entry_key);
            Self::egress(p,&mut self.entrylist[entry_key].0)
        } else {
            self.gc(now);
            let global_port = self.rlhash.get_empty_port(&p);
            match global_port {
                Some(port) => {
                    self._insert_and_egress(now, p, flags, port, li.lk)
                }
                None => {
                    self.write_log(format!("[{}]{} no_empty_port: {} -> {}\n", self.name, now, AddrPort::from_t(p.src_tuple), li.lk));
                    None
                }
            }
        }
    }
    fn egress<'a>(p: PacketInfo, entry:&mut NatEntry<LK>) ->  Option<u16> {
        entry.packets_sent += 1;
        entry.bytes_sent += p.size as u32;
        Some(entry.global_port)
    }
    fn update_connstate(&mut self, is_ingress: bool, conntuple: (u16, (Ipv4Addr, u16)), flags: u8, now: u64, entry_key: DefaultKey){
        if let Some(&conn_key) = self.connhash.get(&conntuple){
            let conn = self.connlist.get_mut(conn_key).unwrap();
            //existing connections are discarded if timed out
            if conn.will_expire < now {
                conn.state_m=TcpStateMachine::new(flags, is_ingress);
            }else{
                conn.state_m.update(flags, is_ingress);
            }
            if is_ingress {return};//don't update timeout if ingress
            let long = conn.state_m.state == TcpState::Established;
            if self.conn_least_longer_than_short_timeout == conn_key {self.conn_least_longer_than_short_timeout = self.connlist.next(self.conn_least_longer_than_short_timeout).unwrap();}
            if long{
                let new = self.connlist.move_to_tail_and_get(conn_key);
                new.will_expire=now+self.idle_timeout_long;
                if self.conn_least_longer_than_short_timeout.is_null() {self.conn_least_longer_than_short_timeout=conn_key};
            }else{
                self.update_least_longer(now);
                let new = self.connlist.move_before_and_get(self.conn_least_longer_than_short_timeout, conn_key);
                new.will_expire=now+self.idle_timeout_short;
                //maybe unnecessary
                //self.update_least_longer(now);
            };
        } else{
            self.push_connstate(is_ingress, conntuple, flags, now, entry_key);
            self.entrylist[entry_key].1+=1;
        };
    }
    fn push_connstate(&mut self, is_ingress: bool, conntuple: (u16, (Ipv4Addr, u16)), flags: u8, now: u64, entry_key: DefaultKey){
        let m = TcpStateMachine::new(flags, is_ingress);
        let long = m.state == TcpState::Established;
        let key = if long{
            let k = self.connlist.push_tail(ConnInfo{state_m: m, will_expire: now+self.idle_timeout_long, belongs_to: entry_key, remote_tuple: conntuple.1});
            if self.conn_least_longer_than_short_timeout.is_null() {self.conn_least_longer_than_short_timeout=k};
            k
        }else{
            self.update_least_longer(now);
            let k = self.connlist.push_before(self.conn_least_longer_than_short_timeout, 
                ConnInfo{state_m: m, will_expire: now+self.idle_timeout_short, belongs_to: entry_key, remote_tuple: conntuple.1});
            self.update_least_longer(now);
            k
        };
        self.connhash.insert(conntuple, key);
    }

    pub fn my_transform_ingress<'a>(&mut self, p: PacketInfo, flags: u8) -> Option<(Ipv4Addr, u16)> {
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let remote_key = self.rlhash.get_lk( p.src_tuple);
        let flags  = flags;
        match self.rlhash.get_remote(RI{global_port:p.dst_tuple.1, nat_key: remote_key}){
            Some(&entry_key) => {
                let conntuple = (self.entrylist[entry_key].0.global_port, p.src_tuple);
                self.update_connstate(true, conntuple, flags, t, entry_key);
                Self::ingress(p, &mut self.entrylist[entry_key].0)},
            None => {self.write_log(format!("[{}]{} ingress_not_found: via {} from {}\n", self.name, t, 
            p.dst_tuple.1, AddrPort::from_t(p.src_tuple))); None}
        }
    }
    fn ingress<'a>(p: PacketInfo, entry:&mut NatEntry<LK>) -> Option<(Ipv4Addr, u16)> {
        entry.packets_received += 1;
        entry.bytes_received += p.size as u32;
        Some(entry.local_tuple)
    }
    pub fn my_transform_icmp_error(&mut self, local_port: u16, remote_addr: Ipv4Addr, remote_port: u16) -> Option<(Ipv4Addr,u16)> {
        let remote_key = self.rlhash.get_lk((remote_addr, remote_port));
        match self.rlhash.get_remote(RI{global_port: local_port, nat_key: remote_key}){
            Some(&entry) => {
                let (e,_) = self.entrylist.get(entry).unwrap();
                return Some(e.local_tuple)},
            None => {None}
        }
    }
    fn update_least_longer(&mut self, now: u64){
        let mut cursor= self.conn_least_longer_than_short_timeout;
        loop{
            if let Some((dat,nex)) = self.connlist.get2(cursor){
            if dat.will_expire >= now+self.idle_timeout_short {break}
                cursor = nex
            }else{break}
        }
        self.conn_least_longer_than_short_timeout = cursor;
    }
    fn gc(&mut self, now: u64){
        self.update_least_longer(now);
        loop{
            if let Some(head) = self.connlist.get(self.connlist.head()){
                if head.will_expire >= now {break}
                let t = self.connlist.pop_head().unwrap();
                self.connhash.remove(&(self.entrylist[t.belongs_to].0.global_port, t.remote_tuple));
                if self.entrylist[t.belongs_to].1 == 1 {
                    let ee = self.entrylist.remove(t.belongs_to).unwrap();
                    self._gc_head_entry(&ee.0, now);
                }else{
                    self.entrylist[t.belongs_to].1 -= 1;
                }
            }else{break}
        }
        self.update_least_longer(now);
    }
    fn _gc_head_entry(&mut self, entry: &NatEntry<LK>, t: u64) {
        self.write_log(format!("[{}]{} removing: via {}: {} -> {}\n", self.name, t, entry.global_port, AddrPort::from_t(entry.local_tuple), entry.nat_key));
        self.rlhash.remove(entry.local_tuple, entry.global_port,entry.nat_key)
    }
    fn _insert_and_egress<'a>(&mut self, now: u64, p: PacketInfo, flags: u8, global_port: u16, nat_key:LK) ->  Option<u16> {

        let entry = NatEntry::new(now, nat_key, p.src_tuple, global_port);
        let k = self.entrylist.insert((entry,1));

        self.push_connstate(false, (global_port, p.dst_tuple ), flags, now, k);

        self.rlhash.insert(k,  p.src_tuple,global_port, nat_key);
        
        self.write_log(format!("[{}]{} inserting: via {}: {} -> {}\n", self.name, now, global_port, AddrPort::from_t(p.src_tuple), nat_key));
        Self::egress(p, &mut self.entrylist.get_mut(k).unwrap().0)
    }
}
