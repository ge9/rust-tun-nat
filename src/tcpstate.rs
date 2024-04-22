use pnet::packet::tcp::TcpFlags::{SYN, ACK, FIN, RST};
#[derive(Eq, PartialEq, Debug)]
pub enum TcpState{
    SynLocal, SynRemote, SynBoth,
    Established,
    Fin1Local, Fin1Remote,
    Fin2Local, Fin2Remote,
    Closed
}
pub struct TcpStateMachine{
    pub state:TcpState
}
impl TcpStateMachine{
    pub fn new(flags: u8, is_ingress : bool) -> Self{
        Self {
            state:if flags & SYN == SYN{
                if is_ingress{
                    TcpState::SynRemote
                }else{
                    TcpState::SynLocal
                }
            }else{
                TcpState::Closed//unknown
            }
        }
    }
    pub fn update(&mut self, flags: u8, ingress : bool) -> bool{//return value indicates whether the state is treated as updated, but currently not used
        if flags & RST == RST {
            self.state=TcpState::Closed; return true
        }
        match self.state{
            TcpState::Closed => if flags & SYN == SYN {
                    if ingress{ 
                        self.state=TcpState::SynRemote
                    }else{ 
                        self.state=TcpState::SynLocal
                    }
                    true
                }else{false}
            TcpState::SynRemote => if flags & SYN == SYN {
                    if !ingress{ 
                        if flags & ACK == ACK{self.state=TcpState::Established} else {self.state=TcpState::SynBoth}
                    }true
                }else{false}
            TcpState::SynLocal => if flags & SYN == SYN {
                    if ingress{ 
                        if flags & ACK == ACK{self.state=TcpState::Established} else {self.state=TcpState::SynBoth}
                    }true
                }else{false}
            TcpState::SynBoth => if flags & (SYN|ACK) == (SYN|ACK) {self.state=TcpState::Established; true}else{false}
            TcpState::Established => if flags & FIN == FIN {
                    if ingress{self.state=TcpState::Fin1Remote}else{self.state=TcpState::Fin1Local}
                    true
                } else if (flags|SYN) == SYN {false}else{true}
            TcpState::Fin1Local => if flags & FIN == FIN {
                if ingress{self.state=TcpState::Fin2Local}
                true
            }else{false}
            TcpState::Fin1Remote => if flags & FIN == FIN {
                if !ingress{self.state=TcpState::Fin2Remote}
                true
            }else{false}
            TcpState::Fin2Local => if flags & ACK == ACK {
                if !ingress{self.state=TcpState::Closed}
                true
            }else{false}
            TcpState::Fin2Remote => if flags & ACK == ACK {
                if ingress{self.state=TcpState::Closed}
                true
            }else{false}
        }
    }
}