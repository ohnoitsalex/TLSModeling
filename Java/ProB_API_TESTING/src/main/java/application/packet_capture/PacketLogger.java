package application.packet_capture;

import org.pcap4j.packet.Packet;

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

}
