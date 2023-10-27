use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{self, EtherType, EtherTypes};
use pnet::packet::Packet;

#[derive(Debug)]
struct NetworkConfig {
    default_interface: Option<NetworkInterface>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        //Get interface list
        let all_interfaces = datalink::interfaces();
        // Get default interface
        let default_interface = all_interfaces
            .iter()
            .find(|default| default.is_up() && !default.is_loopback() && !default.ips.is_empty());

        NetworkConfig {
            default_interface: default_interface.cloned(),
        }
    }
}

impl NetworkConfig {
    fn capture_arp_packets(&self) {
        match &self.default_interface {
            Some(interface) => {
                let (_, mut package_receiver) =
                    match datalink::channel(&interface, Default::default()) {
                        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
                        _ => {
                            eprintln!(
                            "Issues with the data-link sender.\nVerify that you are in ROOT mode."
                        );
                            return;
                        }
                    };
                // Capture ARP Package in the local red.
                loop {
                    match package_receiver.next() {
                        Ok(packet) => {
                            let ethernet = ethernet::EthernetPacket::new(packet);
                            match ethernet {
                                Some(eth_pkt) => {
                                    if eth_pkt.get_ethertype() == EtherTypes::Arp {
                                        let arp_packet = ArpPacket::new(eth_pkt.payload());
                                        match arp_packet {
                                            Some(arp) => {
                                                if arp.get_operation() == ArpOperations::Request {
                                                    // Handle ARP Request
                                                    println!(
                                                        "ARP Request: Who has {}? Tell {}",
                                                        arp.get_target_proto_addr(),
                                                        arp.get_sender_proto_addr()
                                                    );
                                                } else if arp.get_operation()
                                                    == ArpOperations::Reply
                                                {
                                                    // Handle ARP Replay
                                                    println!(
                                                        "ARP Replay: {} is at {}",
                                                        arp.get_sender_proto_addr(),
                                                        eth_pkt.get_source()
                                                    );
                                                }
                                            }
                                            None => {
                                                eprintln!("Issues with IPs.");
                                            }
                                        }
                                    }
                                    // println!("{:?}", eth_pkt);
                                    // Extraction EthernetType
                                    // println!("{}", EtherType::new(34525));
                                }
                                None => {
                                    eprintln!("Issues with Ethernet Packet.");
                                }
                            }
                        }
                        Err(e) => eprintln!("Error Packet Receiver: {}", e),
                    }
                }
            }
            None => {
                eprintln!("No suitable default interface found in config.");
                return;
            }
        }
    }
}

fn main() {
    // Analyze layer 2, ARP operate in layer 2.
    // Create an instance of NetworkConfig using default value
    let config = NetworkConfig::default();
    config.capture_arp_packets();
}
