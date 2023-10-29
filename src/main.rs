use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{self, EtherTypes};
use pnet::packet::Packet;
use serde_json;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

// Defining the NetworkConfig structure
pub struct NetworkConfig {
    pub default_interface: Option<NetworkInterface>,
    pub arp_request_data: HashMap<String, String>,
    pub arp_response_data: HashMap<String, String>,
}

impl NetworkConfig {
    fn new() -> NetworkConfig {
        let default_interface = NetworkConfig::find_default_interface();
        let arp_request_data = HashMap::new();
        let arp_response_data = HashMap::new();
        NetworkConfig {
            default_interface,
            arp_request_data,
            arp_response_data,
        }
    }

    fn find_default_interface() -> Option<NetworkInterface> {
        // Get list of network interfaces
        let all_interfaces = datalink::interfaces();
        // Find the default interface
        let default_interface = all_interfaces
            .iter()
            .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
            .cloned();
        default_interface
    }

    pub fn capture_arp_packets(&mut self) {
        match &self.default_interface {
            Some(interface) => {
                let (_, mut package_receiver) = NetworkConfig::open_data_channel(&interface);
                self.process_arp_packets(&mut package_receiver);
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

    fn process_arp_packets(&mut self, package_receiver: &mut Box<dyn datalink::DataLinkReceiver>) {
        // Capture ARP packages in the local network
        loop {
            match package_receiver.next() {
                Ok(packet) => {
                    let ethernet = ethernet::EthernetPacket::new(packet);
                    if let Some(eth_pkt) = ethernet {
                        if eth_pkt.get_ethertype() == EtherTypes::Arp {
                            self.handle_arp_packet(&eth_pkt);
                        }
                    } else {
                        eprintln!("Issues with Ethernet Packet.");
                    }
                }
                Err(e) => eprintln!("Error Packet Receiver: {}", e),
            }
        }
    }

    fn handle_arp_packet(&mut self, eth_pkt: &ethernet::EthernetPacket) {
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

                        let data = format!(
                            "ARP Request ==> (Date: {:?} Time: {:?}, Elapsed Time: {:?}):\n\
                             Sender IP Address: {}\n\
                             Sender MAC Address: {}\n\
                             Target IP Address: {}\n\
                             Target MAC Address: {}\n\
                             Protocol Type: {}\n",
                            formatted_time.date(),
                            formatted_time.time(),
                            elapsed_time,
                            arp.get_sender_proto_addr(),
                            arp.get_sender_hw_addr(),
                            arp.get_target_proto_addr(),
                            arp.get_target_hw_addr(),
                            arp.get_protocol_type()
                        );

                        self.arp_request_data.insert(
                            String::from("ARP Request"),
                            serde_json::to_string_pretty(&data).unwrap(),
                        );
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

                        let data = format!(
                            "ARP Response (Date: {:?} Time: {:?}, Elapsed Time: {:?}):\n\
                             Sender IP Address: {}\n\
                             Sender MAC Address: {}\n",
                            formatted_time.date(),
                            formatted_time.time(),
                            elapsed_time,
                            arp.get_sender_proto_addr(),
                            arp.get_sender_hw_addr()
                        );

                        self.arp_response_data.insert(
                            String::from("ARP Response"),
                            serde_json::to_string_pretty(&data).unwrap(),
                        );
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

    pub fn write_arp_data_to_directory(&self, directory: &str) -> io::Result<()> {
        // Create the folder if it does not exist
        fs::create_dir_all(directory)?;

        // Full paths of output files
        let arp_request_file = format!("{}/arp_request.json", directory);
        let arp_response_file = format!("{}/arp_response.json", directory);

        // Write data to files
        self.write_data_to_file(&arp_request_file, &self.arp_request_data)?;
        self.write_data_to_file(&arp_response_file, &self.arp_response_data)?;

        Ok(())
    }

    fn write_data_to_file(
        &self,
        file_name: &str,
        data: &HashMap<String, String>,
    ) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(file_name)?;

        for (_, packet_data) in data {
            file.write_all(packet_data.as_bytes())?;
            file.write_all(b"\n")?;
        }
        Ok(())
    }
}

fn main() {
    let mut network_config = NetworkConfig::new();
    network_config.capture_arp_packets();

    // Output folder name
    let output_directory = "output_folder_arp_capture";
    network_config
        .write_arp_data_to_directory(output_directory)
        .unwrap();
}
