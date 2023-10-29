use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{self, EtherTypes};
use pnet::packet::Packet;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

// Definición de la estructura NetworkConfig
struct NetworkConfig {
    default_interface: Option<NetworkInterface>,
}

impl NetworkConfig {
    fn new() -> NetworkConfig {
        // Obtener la interfaz de red predeterminada
        let default_interface = NetworkConfig::find_default_interface();
        NetworkConfig { default_interface }
    }

    fn find_default_interface() -> Option<NetworkInterface> {
        // Obtener la lista de interfaces de red
        let all_interfaces = datalink::interfaces();
        // Encontrar la interfaz predeterminada
        let default_interface = all_interfaces
            .iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .cloned();
        default_interface
    }

    fn capture_arp_packets(&self) {
        match &self.default_interface {
            Some(interface) => {
                let (_, mut package_receiver) = NetworkConfig::open_data_channel(&interface);
                NetworkConfig::process_arp_packets(&mut package_receiver);
            }
            None => {
                eprintln!("No suitable default interface found in config.");
            }
        }
    }

    fn open_data_channel(
        interface: &NetworkInterface,
    ) -> (
        Box<dyn datalink::DataLinkSender>,
        Box<dyn datalink::DataLinkReceiver>,
    ) {
        match datalink::channel(interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            _ => {
                eprintln!("Issues with the data-link sender.\nVerify that you are in ROOT mode.");
                std::process::exit(1);
            }
        }
    }

    fn process_arp_packets(package_receiver: &mut Box<dyn datalink::DataLinkReceiver>) {
        // Capture ARP packages in the local network
        loop {
            match package_receiver.next() {
                Ok(packet) => {
                    let ethernet = ethernet::EthernetPacket::new(packet);
                    if let Some(eth_pkt) = ethernet {
                        if eth_pkt.get_ethertype() == EtherTypes::Arp {
                            NetworkConfig::handle_arp_packet(&eth_pkt);
                        }
                    } else {
                        eprintln!("Issues with Ethernet Packet.");
                    }
                }
                Err(e) => eprintln!("Error Packet Receiver: {}", e),
            }
        }
    }

    fn handle_arp_packet(eth_pkt: &ethernet::EthernetPacket) {
        let start_time = Instant::now();

        let arp_packet = ArpPacket::new(eth_pkt.payload());
        if let Some(arp) = arp_packet {
            let operation = arp.get_operation();
            let elapsed_time = start_time.elapsed();
            let current_time = SystemTime::now();

            if let Ok(duration) = current_time.duration_since(UNIX_EPOCH) {
                let unix_timestamp = duration.as_secs();
                let formatted_time = OffsetDateTime::from_unix_timestamp(unix_timestamp as i64)
                    .ok()
                    .unwrap();

                match operation {
                    ArpOperations::Request => {
                        println!(
                            "ARP Request (Date: {:?} Time: {:?}, Elapsed Time: {:?}):",
                            formatted_time.date(),
                            formatted_time.time(),
                            elapsed_time
                        );
                        println!("  Sender IP Address: {}", arp.get_sender_proto_addr());
                        println!("  Sender MAC Address: {}", arp.get_sender_hw_addr());
                        println!("  Target IP Address: {}", arp.get_target_proto_addr());
                        println!("  Target MAC Address: {}", arp.get_target_hw_addr());
                        println!("  Protocol Type: {}", arp.get_protocol_type());
                    }
                    ArpOperations::Reply => {
                        println!(
                            "ARP Response (Date: {:?} Time: {:?}, Elapsed Time: {:?}):",
                            formatted_time.date(),
                            formatted_time.time(),
                            elapsed_time
                        );
                        println!("  Sender IP Address: {}", arp.get_sender_proto_addr());
                        println!("  Sender MAC Address: {}", arp.get_sender_hw_addr());
                    }
                    _ => {
                        eprintln!("Unknown ARP operation.");
                    }
                }
            } else {
                eprintln!("Error obtaining system time.");
            }
        } else {
            eprintln!("Issues with ARP Packet.");
        }
    }
}

fn main() {
    let network_config = NetworkConfig::new();
    network_config.capture_arp_packets();
}
