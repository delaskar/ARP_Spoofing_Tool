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
pub enum IPError {
    InvalidFormat,
    OutOfRange,
    IncorrectNumberOfOctets,
    NoInterfaceExtracted,
    PacketNotReceived,
}

impl fmt::Display for IPError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            IPError::InvalidFormat => writeln!(f, "Error: Invalid IPv4 address format."),
            IPError::OutOfRange => writeln!(f, "Error: Octet values out of range."),
            IPError::IncorrectNumberOfOctets => writeln!(f, "Error: Incorrect number of octets"),
            IPError::NoInterfaceExtracted => {
                writeln!(f, "Error while finding the default interface.")
            }
            IPError::PacketNotReceived => writeln!(f, "Packet NOT received!"),
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

fn network_info() -> Result<(IpAddr, MacAddr), IPError> {
    let interfaces = datalink::interfaces();

    let default_interface = interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());

    match default_interface {
        Some(interface) => {
            let default_mac = match interface.mac {
                Some(mac) => mac,
                None => MacAddr::zero(),
            };
            let default_ip = interface.ips[0].ip();

            Ok((default_ip, default_mac))
        }
        None => Err(IPError::NoInterfaceExtracted),
    }
}

fn ip_and_mac_default() -> (Ipv4Addr, MacAddr) {
    let net_data = match network_info() {
        Ok(data) => data,
        Err(_) => {
            // Default value or an example of IP and MAC address in case of error
            (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), MacAddr::zero())
        }
    };

    let (ip, mac) = net_data;
    let ipv4_address: Ipv4Addr = match ip {
        IpAddr::V4(addr) => addr,
        _ => Ipv4Addr::new(0, 0, 0, 0), // Default value if the IP is not V4 type
    };

    (ipv4_address, mac)
}

pub fn get_victim_mac_address(ip_victim: String) -> Result<MacAddr, IPError> {
    // Default Host guest details
    let (ip, mac) = ip_and_mac_default();

    // Victim IPv4
    let ip_victim = verify_ip_address(ip_victim);

    let sender_mac = mac;
    let sender_ip = ip;
    let target_ip = match ip_victim {
        Ok(ip) => Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
        _ => Ipv4Addr::LOCALHOST,
    };

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

    let mut received = false;
    let mut victim_mac = MacAddr::zero();

    while !received {
        match package_receiver.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                if ethernet.get_destination() == sender_mac {
                    if ethernet.get_ethertype() == EtherTypes::Arp {
                        victim_mac = ethernet.get_source();
                        received = true;
                    }
                }
            }
            _ => eprintln!("Packet NOT received!"),
        }
    }

    if !received {
        Err(IPError::PacketNotReceived)
    } else {
        Ok(victim_mac)
    }
}
