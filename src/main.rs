use std::io;

const PROTO_IPV4: u16 = 0x0800;
const PROTO_TCP: u8 = 0x06;
const ETH_HEADER_BYTES: usize = 4;

fn main() -> io::Result<()> {
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

        match etherparse::Ipv4HeaderSlice::from_slice(&mut buf[ETH_HEADER_BYTES..nbytes]) {
            Ok(p) => {
                let src = p.source_addr();
                let dst = p.destination_addr();
                let proto = p.protocol();
                let payload_len = p.payload_len();
                if proto != PROTO_TCP {
                    /* only handle tcp now */
                    eprintln!("ignoreing packet proto {:?}", proto);
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&mut buf[ETH_HEADER_BYTES + p.slice().len()..nbytes]) {
                    Ok(p) => {
                        eprintln!(
                            "{} -> {} {}b of tcp from port {} to {}",
                            src,
                            dst,
                            payload_len,
                            p.source_port(),
                            p.destination_port(),
                        );
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
