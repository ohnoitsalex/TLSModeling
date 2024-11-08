package application.packetcapture;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.TcpPacket;


import java.util.Arrays;


public class PacketSniffer {

    public static void main (String[] args) throws NotOpenException, PcapNativeException {
        setUpNetworkInterface("lo0","tcp port 1234");
    }

    public static void setUpNetworkInterface(String networkInterface, String filterPort) throws PcapNativeException, NotOpenException {
        // Get the network interface (replace with your network interface name)
        PcapNetworkInterface nif = Pcaps.getDevByName("lo0");  // Replace with the correct interface name
        if (nif == null) {
            System.out.println("No network interface found.");
            return;
        }

        int snapLen = 65536; // Capture all packets, no truncation
        int timeout = 10; // Timeout in milliseconds
        PcapHandle handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

        // Set a filter to capture only TCP packets on port 443 (TLS/HTTPS)
        handle.setFilter("tcp port 1234", BpfProgram.BpfCompileMode.OPTIMIZE);

        System.out.println("Starting packet capture. Listening for TLS handshake packets on port 443...");

        while (true) {
            Packet packet = handle.getNextPacket();
            if (packet != null && packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);

                // Check if the TCP payload contains TLS records
                if (tcpPacket.getPayload() != null) {
                    Packet payload = tcpPacket.getPayload();

                    // Check if the payload is a raw TLS record (starting with record type 0x16 for Handshake)
                    if (payload.getRawData().length > 0) {
                        byte[] rawData = payload.getRawData();
                        if (rawData[0] == (byte) 0x16) { // 0x16 indicates a TLS Handshake record
                            System.out.println("Captured a TLS Handshake Packet (0x16):");

                            // Output the raw bytes of the packet (this is for diagnostic purposes)
                            System.out.println("Raw TLS Handshake Data: ");
                            for (byte b : rawData) {
                                System.out.printf("%02x ", b);
                            }
                            System.out.println("\n");

                            // Further parsing logic could go here to decode the Client Hello or Server Hello messages
                        }
                    }
                }
            }
        }
    }
}
