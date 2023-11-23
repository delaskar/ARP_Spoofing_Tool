mod arp_spoofing_modules;

pub use crate::arp_spoofing_modules::arp_capture;
pub use crate::arp_spoofing_modules::get_victim_data;

fn main() {
    let victim_ip_address = String::from("127.0.0.1");

    // Test get_victim_mac_address
    let mac_victim = get_victim_data::get_victim_mac_address(victim_ip_address);
    println!("{:?}", mac_victim);

    let mut network_config = arp_capture::NetworkConfig::new();
    network_config.capture_arp_packets();

    // Output folder name
    let output_directory = "output_folder_arp_capture";
    network_config
        .write_arp_data_to_directory(output_directory)
        .unwrap();
}
