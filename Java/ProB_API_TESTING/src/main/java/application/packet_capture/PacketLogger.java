package application.packet_capture;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class PacketLogger {

    // Method to print the raw bytes of the TLS Handshake data
    public static void printRawTlsData(Packet payload) {
        byte[] rawData = payload.getRawData();
        System.out.println("Raw TLS Handshake Data:");
        for (byte b : rawData) {
            System.out.printf("%02x ", b);
        }
        System.out.println();  // Newline after printing the data
    }

    // Method to write the raw bytes of the TLS Handshake data to a file
    public static void writeRawTlsDataToFile(Packet payload, String filePath) {
        byte[] rawData = payload.getRawData();

        // Open a BufferedWriter to write to the file
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath, true))) {
            writer.write("Raw TLS Handshake Data:\n");

            // Write each byte in hexadecimal format
            for (byte b : rawData) {
                writer.write(String.format("%02x ", b));
            }
            writer.newLine(); // Add a newline after the data

            System.out.println("TLS Handshake Data written to " + filePath);

        } catch (IOException e) {
            System.err.println("Error writing TLS Handshake Data to file: " + e.getMessage());
        }
    }

    //Method that reformats the raw data in a readable and comparable way. Need to test out the data first before implementing
    public static void reformatRawData(Packet payload){

    }

    // Helper method to extract headers from IP and TCP layers
    public static String extractHeaders(Packet packet) {
        StringBuilder headers = new StringBuilder();

        // Extract IP header information (IPv4 or IPv6)
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            headers.append("IPv4 Src: ").append(ipV4Packet.getHeader().getSrcAddr())
                    .append(" -> Dst: ").append(ipV4Packet.getHeader().getDstAddr()).append("\n");
        } else if (packet.contains(IpV6Packet.class)) {
            IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
            headers.append("IPv6 Src: ").append(ipV6Packet.getHeader().getSrcAddr())
                    .append(" -> Dst: ").append(ipV6Packet.getHeader().getDstAddr()).append("\n");
        }

        // Extract TCP header information
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcpPacket = packet.get(TcpPacket.class);
            headers.append("TCP Src Port: ").append(tcpPacket.getHeader().getSrcPort())
                    .append(" -> Dst Port: ").append(tcpPacket.getHeader().getDstPort()).append("\n")
                    .append("Sequence Number: ").append(tcpPacket.getHeader().getSequenceNumber()).append("\n")
                    .append("Acknowledgment Number: ").append(tcpPacket.getHeader().getAcknowledgmentNumber()).append("\n");
        }

        return headers.toString();
    }
    // Helper method to log headers and raw payload data to a file
    public static void logPacketData(String headers, Packet payload, String filePath) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath, true))) {
            writer.write("=== TLS Handshake Packet ===\n");
            writer.write(headers);  // Write header information

            TlsHandshakeParser.parseTlsHandshakeRecord(payload.getRawData());
            writer.write("Raw TLS Handshake Data:\n");
            for (byte b : payload.getRawData()) {
                writer.write(String.format("%02x ", b));
            }
            writer.newLine();
            writer.write("===========================\n");
            writer.newLine();

            System.out.println("TLS Handshake Packet logged to " + filePath);

        } catch (IOException e) {
            System.err.println("Error writing packet data to file: " + e.getMessage());
        }
    }
}
