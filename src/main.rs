use ndisapi::{EthPacket, EthRequestMut, IntermediateBuffer, MacAddress, Ndisapi};
use std::fs::OpenOptions;
use std::io::Write;
use std::mem::transmute;
use std::thread::sleep;
use std::time::Duration;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject};

fn main() -> windows::core::Result<()> {
    let ndis = Ndisapi::new("NDISRD").expect("Failed to create NdisApi instance");

    let adapters = ndis
        .get_tcpip_bound_adapters_info()
        .expect("Failed to enumerate adapters");

    let adapter_handle = adapters[0].get_handle();

    let mut event: HANDLE;
    unsafe {
        event = CreateEventW(None, true, false, None)?;
    }

    let setpack = ndis.set_packet_event(unsafe { transmute(adapter_handle) }, unsafe {
        transmute(event)
    });

    let tunnel = ndis.set_adapter_mode(
        adapter_handle,
        ndisapi::FilterFlags::MSTCP_FLAG_SENT_RECEIVE_TUNNEL
            | ndisapi::FilterFlags::MSTCP_FLAG_FILTER_DIRECT,
    );

    if tunnel.is_err() {
        eprintln!("Failed to set adapter mode: {:?}", tunnel);
    }

    println!("hey{:?}", tunnel);
    println!("hey{:?}", setpack);

    let mut packet = IntermediateBuffer::default();

    // Log dosyasını aç
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("packet_log.txt")
        .expect("Log dosyası açılamadı!");

    println!("Paket okuma döngüsü başlatılıyor...");

    loop {
        sleep(Duration::from_secs(1));

        loop {
            let mut read_request = EthRequestMut::new(adapter_handle);
            read_request.set_packet(&mut packet);

            // Paket okuma işlemi
            if ndis.read_packet(&mut read_request).is_err() {
                break; // Kuyrukta başka paket yoksa döngüden çık
            }

            // Paketin boyutunu ve ham verisini ekrana ve log dosyasına yazdır
            let log_entry = format!(
                "Paket okundu ({} bytes): {:?}\n",
                packet.get_length(),
                packet.get_data()
            );
            println!("{}", log_entry);
            log_file
                .write_all(log_entry.as_bytes())
                .expect("Log dosyasına yazılamadı");
        }

        // Olayı sıfırlayın ve yeni paketlerin gelmesini bekleyin
        unsafe { ResetEvent(event) };
    }

    unsafe { CloseHandle(event) };

    Ok(())
}
