use pnet::datalink::{self, Channel::Ethernet as OtherEthernet};
use pnet::packet::arp::{Arp, ArpHardwareType, ArpOperations};
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel, TransportChannelType};
use pnet::util::MacAddr;
use std::error;
use std::fmt;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::net::Ipv4Addr;

#[derive(Debug)]
enum IPError {
    InvalidFormat,
    OutOfRange,
    IncorrectNumberOfOctets,
}

impl fmt::Display for IPError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            IPError::InvalidFormat => write!(f, "Error: Invalid IPv4 address format."),
            IPError::OutOfRange => write!(f, "Error: Octet values out of range."),
            IPError::IncorrectNumberOfOctets => write!(f, "Error: Incorrect number of octets"),
        }
    }
}

// Trait "std::error::Error" implement for define custom type.
impl error::Error for IPError {}

fn create_arp_packet(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Arp {
    Arp {
        hardware_type: ArpHardwareType::new(1),
        protocol_type: EtherType(0x0800),
        hw_addr_len: 6,
        proto_addr_len: 4,
        operation: ArpOperations::Request,
        sender_hw_addr: sender_mac,
        sender_proto_addr: sender_ip,
        target_hw_addr: MacAddr::zero(),
        target_proto_addr: target_ip,
        payload: Vec::new(),
    }
}

fn create_ethernet_packet<'a>(
    ethernet_buffer: &'a mut [u8],
    sender_mac: MacAddr,
    arp_packet: &Arp,
) -> MutableEthernetPacket<'a> {
    let mut ethernet_packet = MutableEthernetPacket::new(ethernet_buffer).unwrap();
    ethernet_packet.set_source(sender_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(&arp_packet.payload);
    ethernet_packet
}

fn verify_ip_address(ip_address: String) -> Result<Vec<u8>, IPError> {
    // Delete white spaces
    let trimmed_input: &str = ip_address.trim();

    // Separate octets entry
    let octets: Vec<&str> = trimmed_input.split('.').collect();

    // Verify its input has 4 octets
    if octets.len() != 4 {
        return Err(IPError::IncorrectNumberOfOctets);
    }

    // Parse every octets to u8 and validate the range
    let mut ip_octets: Vec<u8> = Vec::new();
    for octet in octets {
        if octet.chars().all(|c| c.is_digit(10)) {
            match octet.parse::<u8>() {
                Ok(value) if (0..=255).contains(&value) => ip_octets.push(value),
                _ => return Err(IPError::OutOfRange),
            }
        } else {
            return Err(IPError::InvalidFormat);
        }
    }
    Ok(ip_octets)
}

pub fn get_victim_mac_address() {
    let sender_mac = MacAddr::new(0x00, 0x0c, 0x29, 0xb8, 0x13, 0xc6);
    let sender_ip = Ipv4Addr::new(192, 168, 1, 166);
    let target_ip = Ipv4Addr::new(192, 168, 1, 131);

    let arp_packet = create_arp_packet(sender_mac, sender_ip, target_ip);
    let mut ethernet_buffer = [0u8; 42];
    let ethernet_packet = create_ethernet_packet(&mut ethernet_buffer, sender_mac, &arp_packet);

    let (mut ts, _tr) = transport_channel(
        65535,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Ipv4),
    )
    .expect("Failed to create transport channel");

    ts.send_to(ethernet_packet.to_immutable(), IpAddr::V4(target_ip))
        .expect("Failed to send ARP request");

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|iface| iface.is_up() && !iface.is_loopback())
        .expect("No suitable network interface found");

    let (_, mut package_receiver) = match datalink::channel(&interface, Default::default()) {
        Ok(OtherEthernet(tx, rx)) => (tx, rx),
        _ => panic!("Issues with the data link sender"),
    };

    loop {
        match package_receiver.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                if ethernet.get_destination() == sender_mac {
                    println!("Received Ethernet packet: {:?}", ethernet);
                    break;
                }
            }
            _ => eprint!("Packet NOT received!"),
        }
    }
}
