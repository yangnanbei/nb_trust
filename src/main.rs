use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;

mod tcp;

const PROTO_IPV4: u16 = 0x0800;
const PROTO_TCP: u8 = 0x06;
const ETH_HEADER_BYTES: usize = 4;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::State> = Default::default();
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        let _ethflags = u16::from_be_bytes([buf[0], buf[1]]);
        let ethproto = u16::from_be_bytes([buf[2], buf[3]]);
        match ethproto != PROTO_IPV4 {
            true => continue,
            false => (),
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[ETH_HEADER_BYTES..nbytes]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                let proto = iph.protocol();
                if proto != PROTO_TCP {
                    /* only handle tcp now */
                    eprintln!("ignoreing packet proto {:?}", proto);
                    continue;
                }

                let ip_hdr_size = iph.slice().len();
                match etherparse::TcpHeaderSlice::from_slice(
                    &buf[ETH_HEADER_BYTES + iph.slice().len()..nbytes],
                ) {
                    Ok(tcph) => {
                        let datai = ETH_HEADER_BYTES + ip_hdr_size + tcph.slice().len();
                        connections
                            .entry(Quad {
                                src: (src, tcph.source_port()),
                                dst: (dst, tcph.destination_port()),
                            })
                            .or_default()
                            .on_packet(iph, tcph, &buf[datai..nbytes]);
                    }
                    Err(e) => {
                        eprintln!("ignoreing weired packet {:?}", e);
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoreing weired packet {:?}", e);
                continue;
            }
        }
    }
    Ok(())
}
