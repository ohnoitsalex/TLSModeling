package application.packetcapture;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.TcpPacket;


import java.util.Arrays;


public class PacketSniffer {

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

            // Step 3: Set the filter for capturing TCP packets on port 443 (TLS/HTTPS)
            setPacketFilter(handle);

            System.out.println("Starting packet capture. Listening for TLS handshake packets on port 443...");

            // Step 4: Start capturing packets
            captureTlsHandshakePackets(handle);

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
            handle.setFilter("tcp port 1234", BpfProgram.BpfCompileMode.OPTIMIZE);
        } catch (PcapNativeException e) {
            System.err.println("Error setting filter: " + e.getMessage());
            throw e;
        } catch (NotOpenException e) {
            throw new RuntimeException(e);
        }
    }

    // Method to capture and process TLS handshake packets
    private static void captureTlsHandshakePackets(PcapHandle handle) {
        while (true) {
            try {
                Packet packet = handle.getNextPacket();
                if (packet != null && packet.contains(TcpPacket.class)) {
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);

                    // Check if the TCP payload contains TLS records
                    if (tcpPacket.getPayload() != null) {
                        Packet payload = tcpPacket.getPayload();

                        // Check if the payload starts with 0x16 (TLS Handshake)
                        if (isTlsHandshakeRecord(payload)) {
                            System.out.println("Captured a TLS Handshake Packet (0x16):");

                            // Output the raw bytes of the packet (for diagnostic purposes)
                            printRawTlsData(payload);
                        }
                    }
                }
            } catch (NotOpenException e) {
                System.err.println("Error capturing packets: " + e.getMessage());
                break;  // Exit the loop if an error occurs
            }
        }
    }

    // Method to check if the payload represents a TLS Handshake record
    private static boolean isTlsHandshakeRecord(Packet payload) {
        byte[] rawData = payload.getRawData();
        return rawData.length > 0 && rawData[0] == (byte) 0x16; // 0x16 indicates a TLS Handshake record
    }

    // Method to print the raw bytes of the TLS Handshake data
    private static void printRawTlsData(Packet payload) {
        byte[] rawData = payload.getRawData();
        System.out.println("Raw TLS Handshake Data:");
        for (byte b : rawData) {
            System.out.printf("%02x ", b);
        }
        System.out.println();  // Newline after printing the data
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
        handle.setFilter("tcp port 443", BpfProgram.BpfCompileMode.OPTIMIZE);

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
