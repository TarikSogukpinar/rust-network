/// This example demonstrates the essential usage of active filtering modes for packet processing. It selects a
/// network interface and sets it into a filtering mode, where both sent and received packets are queued. The example
/// registers a Win32 event using the `Ndisapi::set_packet_event` function, and enters a waiting state for incoming packets.
/// Upon receiving a packet, its content is decoded and displayed on the console screen, providing a real-time view of
/// the network traffic.
use clap::Parser;
use ndisapi::{
    DirectionFlags,
    EthRequest,
    EthRequestMut,
    FilterFlags,
    IntermediateBuffer,
    Ndisapi,
};
use smoltcp::wire::{
    ArpPacket,
    EthernetFrame,
    EthernetProtocol,
    Icmpv4Packet,
    Icmpv6Packet,
    IpProtocol,
    Ipv4Packet,
    Ipv6Packet,
    TcpPacket,
    UdpPacket,
};
use windows::{
    core::Result,
    Win32::Foundation::{ CloseHandle, HANDLE },
    Win32::System::Threading::{ CreateEventW, ResetEvent, WaitForSingleObject },
};
use std::mem::transmute;
use std::thread::sleep;
use std::time::Duration;

#[derive(Parser)]
struct Cli {
    /// Network interface index (please use listadapters example to determine the right one)
    #[clap(short, long)]
    interface_index: usize,
    /// Number of packets to read from the specified network interface
    #[clap(short, long)]
    packets_number: usize,
}

fn main() -> anyhow::Result<()> {
    // Parse command line arguments and extract interface index and number of packets
    let Cli { mut interface_index, mut packets_number } = Cli::parse();

    // Subtract 1 from interface index to convert from 1-based to 0-based indexing
    interface_index -= 1;

    // Create new NDISAPI object using the WinpkFilter driver
    let driver = Ndisapi::new("NDISRD").expect(
        "WinpkFilter driver is not installed or failed to load!"
    );

    // Print the version of Windows Packet Filter detected by the driver API
    println!("Detected Windows Packet Filter version {}", driver.get_version()?);

    // Get information about TCP/IP adapters bound to the driver
    let adapters = driver.get_tcpip_bound_adapters_info()?;

    println!("Mevcut adaptörler:");
    for (index, adapter) in adapters.iter().enumerate() {
        println!("Index {}: {}", index + 1, adapter.get_name());
    }

    // If the specified interface index is greater than the number of available interfaces, panic with an error message
    if interface_index + 1 > adapters.len() {
        panic!("Interface index is beyond the number of available interfaces");
    }

    // Print a message showing the interface name and the number of packets being used.
    println!(
        "Using interface {} with {} packets",
        adapters[interface_index].get_name(),
        packets_number
    );

    // Create a Win32 event for packet handling.
    let event: HANDLE;
    unsafe {
        event = CreateEventW(None, true, false, None)?; // Creating a Win32 event without a name.
    }

    // Set the created event within the driver to signal completion of packet handling.
    driver.set_packet_event(adapters[interface_index].get_handle(), unsafe { transmute(event) })?;

    // Put the network interface into tunnel mode by setting it's filter flags.
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL
    )?;

    // Allocate single IntermediateBuffer on the stack
    let mut packet = IntermediateBuffer::default();

    // Loop through all the packets from the network until we are done.
    while packets_number > 0 {
        unsafe {
            WaitForSingleObject(event, u32::MAX); // Wait for the event to finish before continuing.
        }

        println!("Waiting for packets...");

        loop {
            // Initialize EthPacketMut to pass to driver API
            let mut read_request = EthRequestMut::new(adapters[interface_index].get_handle());

            read_request.set_packet(&mut packet);

            if driver.read_packet(&mut read_request).is_err() {
                println!("No more packets in the queue.");
                break;
            }

            // Store the direction flags
            let direction_flags = packet.get_device_flags();

            // Print packet information
            if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                println!(
                    "\nMSTCP --> Interface ({} bytes) remaining packets {}\n",
                    packet.get_length(),
                    packets_number
                );
            } else {
                println!(
                    "\nInterface --> MSTCP ({} bytes) remaining packets {}\n",
                    packet.get_length(),
                    packets_number
                );
            }

            // Decrement the number of packets.
            packets_number -= 1;

            // Print some information about the sliced packet
            print_packet_info(&packet);

            let mut write_request = EthRequest::new(adapters[interface_index].get_handle());
            write_request.set_packet(&packet);

            // Re-inject the packet back into the network stack
            if direction_flags == DirectionFlags::PACKET_FLAG_ON_SEND {
                match driver.send_packet_to_adapter(&write_request) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to adapter. Error code = {err}"),
                };
            } else {
                match driver.send_packet_to_mstcp(&write_request) {
                    Ok(_) => {}
                    Err(err) => println!("Error sending packet to mstcp. Error code = {err}"),
                }
            }

            // Check if we're done filtering all packets, and then break out of the loop.
            if packets_number == 0 {
                println!("Filtering complete\n");
                break;
            }

            sleep(Duration::from_secs(500));
        }

        let _ = unsafe {
            ResetEvent(event) // Reset the event to continue waiting for packets to arrive.
        };
    }

    // Put the network interface into default mode.
    driver.set_adapter_mode(
        adapters[interface_index].get_handle(),
        FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL | FilterFlags::MSTCP_FLAG_FILTER_DIRECT
    )?;

    let _ = unsafe {
        CloseHandle(event) // Close the event handle.
    };

    // Return the result.
    Ok(())
}

fn print_packet_info(packet: &IntermediateBuffer) {
    if packet.get_length() < 5_000_000 {
        return;
    }

    let eth_hdr = EthernetFrame::new_unchecked(packet.get_data());
    match eth_hdr.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new_unchecked(eth_hdr.payload());
            println!("  Ipv4 {:?} => {:?}", ipv4_packet.src_addr(), ipv4_packet.dst_addr());
            match ipv4_packet.next_header() {
                IpProtocol::Icmp => {
                    let icmp_packet = Icmpv4Packet::new_unchecked(ipv4_packet.payload());
                    println!(
                        "ICMPv4: Type: {:?} Code: {:?}",
                        icmp_packet.msg_type(),
                        icmp_packet.msg_code()
                    );
                }
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload());
                    println!("   TCP {:?} -> {:?}", tcp_packet.src_port(), tcp_packet.dst_port());
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload());
                    println!("   UDP {:?} -> {:?}", udp_packet.src_port(), udp_packet.dst_port());
                }
                _ => {
                    println!("Unknown IPv4 packet: {:?}", ipv4_packet);
                }
            }
        }
        EthernetProtocol::Ipv6 => {
            let ipv6_packet = Ipv6Packet::new_unchecked(eth_hdr.payload());
            println!("  Ipv6 {:?} => {:?}", ipv6_packet.src_addr(), ipv6_packet.dst_addr());
            match ipv6_packet.next_header() {
                IpProtocol::Icmpv6 => {
                    let icmpv6_packet = Icmpv6Packet::new_unchecked(ipv6_packet.payload());
                    println!(
                        "ICMPv6 packet: Type: {:?} Code: {:?}",
                        icmpv6_packet.msg_type(),
                        icmpv6_packet.msg_code()
                    );
                }
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv6_packet.payload());
                    println!("   TCP {:?} -> {:?}", tcp_packet.src_port(), tcp_packet.dst_port());
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv6_packet.payload());
                    println!("   UDP {:?} -> {:?}", udp_packet.src_port(), udp_packet.dst_port());
                }
                _ => {
                    println!("Unknown IPv6 packet: {:?}", ipv6_packet);
                }
            }
        }
        EthernetProtocol::Arp => {
            let arp_packet = ArpPacket::new_unchecked(eth_hdr.payload());
            println!("ARP packet: {:?}", arp_packet);
        }
        EthernetProtocol::Unknown(_) => {
            println!("Unknown Ethernet packet: {:?}", eth_hdr);
        }
    }
}
