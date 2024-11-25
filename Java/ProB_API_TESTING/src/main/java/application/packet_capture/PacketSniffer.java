package application.packet_capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.TcpPacket;

import java.util.ArrayList;
import java.util.List;


public class PacketSniffer {

    private static List<Packet> TLSPacketList = new ArrayList<>(); // List to store packets

    public static void main (String[] args) throws NotOpenException, PcapNativeException {
        //setUpNetworkInterface("lo0","tcp port 1234");
        try {
            // Step 1: Get the network interface
            PcapNetworkInterface networkInterface = getNetworkInterface("lo0");
            if (networkInterface == null) {
                System.out.println("No network interface found.");
                return;
            }
            // Step 2: Open the network interface for packet capture
            PcapHandle handle = openCaptureHandle(networkInterface);

            // Step 3: Set the filter for capturing TCP packets on port 1234 (TLS/HTTPS)
            setPacketFilter(handle);

            System.out.println("Starting packet capture. Listening for TLS handshake packets on port 1235...");

            // Step 4: Start capturing packets
            captureTlsHandshakePackets(handle);

            // Step 5: Log Packets
            logPacket();

        } catch (PcapNativeException | NotOpenException e) {
            System.err.println("Error opening network interface or capturing packets: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Method to retrieve the network interface by name
    private static PcapNetworkInterface getNetworkInterface(String interfaceName) throws PcapNativeException {
        PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
        if (nif == null) {
            System.out.println("No network interface found with name: " + interfaceName);
        }
        return nif;
    }

    // Method to open a capture handle for a given network interface
    private static PcapHandle openCaptureHandle(PcapNetworkInterface networkInterface) throws PcapNativeException, NotOpenException {
        int snapLen = 65536; // Capture all packets, no truncation
        int timeout = 10;    // Timeout in milliseconds
        return networkInterface.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
    }

    // Method to set the packet filter to capture only TCP packets on port 443 (TLS/HTTPS)
    private static void setPacketFilter(PcapHandle handle) throws PcapNativeException {
        try {
            handle.setFilter("tcp port 1235", BpfProgram.BpfCompileMode.OPTIMIZE);
        } catch (PcapNativeException e) {
            System.err.println("Error setting filter: " + e.getMessage());
            throw e;
        } catch (NotOpenException e) {
            throw new RuntimeException(e);
        }
    }

    // Method to capture and process TLS handshake packets with headers
    private static void captureTlsHandshakePackets(PcapHandle handle) {
        System.out.println("Starting TLS Handshake packet capture...");

        //Set to 10 seconds of packet capture
        int captureDuration = 16; // Duration to capture packets in seconds
        long startTime = System.currentTimeMillis();
        long endTime = startTime + captureDuration * 1000;

        while (System.currentTimeMillis() < endTime) {
            try {
                Packet packet = handle.getNextPacket();
                if (packet == null) {
                    continue; // Skip if no packet is captured
                }

                // Process TCP packets that may contain TLS data
                if (packet.contains(TcpPacket.class)) {
                    System.out.println("FOUND TCP PACKET");
//                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
//                    Packet payload = tcpPacket.getPayload();

                    // Check for a TCP payload that starts with TLS Handshake type (0x16)
                    if (packet.get(TcpPacket.class).getPayload() != null && packet.get(TcpPacket.class).getPayload().getRawData().length > 0 && packet.get(TcpPacket.class).getPayload().getRawData()[0] == (byte) 0x16) {
                        System.out.println("Captured a TLS Handshake Packet:");
                        TLSPacketList.add(packet);
//                        // Extract header information
//                        String headers = PacketLogger.extractHeaders(packet);
//                        System.out.println("Extracted Headers");
//
//                        // Log headers and raw data to file
//                        PacketLogger.logPacketData(headers, payload, "tls_handshake_data.txt");
                    }
                }
            } catch (NotOpenException e) {
                System.err.println("Error capturing packets: " + e.getMessage());
                break;
            } catch (Exception e) {
                System.err.println("Unexpected error: " + e.getMessage());
            }
        }
    }

    private static void logPacket(){
        for (int i = 0; i < TLSPacketList.size(); i++){
            Packet currentPacket = TLSPacketList.get(i);
            String headers = PacketLogger.extractHeaders(currentPacket);
            System.out.println("Extracted Headers");
            TcpPacket tcpPacket = currentPacket.get(TcpPacket.class);
            Packet payload = tcpPacket.getPayload();

            // Log headers and raw data to file
            PacketLogger.logPacketData(headers, payload, "tls_handshake_data.txt");
        }
    }
    // Method to check if the payload represents a TLS Handshake record
    private static boolean isTlsHandshakeRecord(Packet payload) {
        byte[] rawData = payload.getRawData();
        return rawData.length > 0 && rawData[0] == (byte) 0x16; // 0x16 indicates a TLS Handshake record
    }

    public static void setUpNetworkInterface(String networkInterface, String filterPort) throws PcapNativeException, NotOpenException {
        // Get the network interface (replace with your network interface name)
        PcapNetworkInterface nif = Pcaps.getDevByName("en0");  // Replace with the correct interface name
        if (nif == null) {
            System.out.println("No network interface found.");
            return;
        }

        int snapLen = 65536; // Capture all packets, no truncation
        int timeout = 10; // Timeout in milliseconds
        PcapHandle handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

        // Set a filter to capture only TCP packets on port 443 (TLS/HTTPS)
        handle.setFilter("tcp port 123", BpfProgram.BpfCompileMode.OPTIMIZE);

        System.out.println("Starting packet capture. Listening for TLS handshake packets on port 1234...");

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
