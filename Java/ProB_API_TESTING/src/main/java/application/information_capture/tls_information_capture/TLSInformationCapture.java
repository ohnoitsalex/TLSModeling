package application.information_capture.tls_information_capture;

import application.information_capture.InformationCapture;
import application.information_converter.InformationConvertertoAbstract;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.ArrayList;
import java.util.List;


public class TLSInformationCapture extends InformationCapture {

    private final List<Packet> TLSPacketList = new ArrayList<>(); // List to store packets

    public TLSInformationCapture() {

    }

    // Method to retrieve the network interface by name
    private PcapNetworkInterface getNetworkInterface(String interfaceName) throws PcapNativeException {
        PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
        if (nif == null) {
            System.out.println("No network interface found with name: " + interfaceName);
        }
        return nif;
    }

    // Method to open a capture handle for a given network interface
    private PcapHandle openCaptureHandle(PcapNetworkInterface networkInterface) throws PcapNativeException, NotOpenException {
        int snapLen = 65536; // Capture all packets, no truncation
        int timeout = 10;    // Timeout in milliseconds
        return networkInterface.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
    }

    // Method to set the packet filter to capture only TCP packets on port 443 (TLS/HTTPS)
    private void setPacketFilter(PcapHandle handle) throws PcapNativeException {
        try {
            handle.setFilter("tcp port 1234", BpfProgram.BpfCompileMode.OPTIMIZE);
        } catch (PcapNativeException e) {
            System.err.println("Error setting filter: " + e.getMessage());
            throw e;
        } catch (NotOpenException e) {
            throw new RuntimeException(e);
        }
    }

    // Method to capture and process TLS handshake packets with headers
    private void captureTlsHandshakePackets(PcapHandle handle) {
        System.out.println("Starting TLS Handshake packet capture...");
        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                // Override function
                // Process TCP packets that may contain TLS data
                if (packet.contains(TcpPacket.class)) {
//                    System.out.println("FOUND TCP PACKET");
                    TcpPacket tcpPacket = packet.get(TcpPacket.class);
                    Packet payload = tcpPacket.getPayload();
                    // Check for a TCP payload that starts with TLS Handshake type (0x16)
                    if (payload != null && isTlsHandshakeRecord(payload)) {
                        System.out.println("Captured a TLS Handshake Packet:");
                        TLSPacketList.add(packet);
                        // Extract header information
                        String headers = PacketLogger.extractHeaders(packet);
//                        System.out.println("Extracted Headers");
                        // Log headers and raw data to file
                        PacketLogger.logPacketData(headers, payload, "data/tls_handshake_data.txt");
                        InformationConvertertoAbstract.configureYAML();
                        InformationConvertertoAbstract.serializeToYAML(TlsHandshakeParser.tlsClientInformationHolder, "data/SUTClientHello");
                        InformationConvertertoAbstract.serializeToYAML(TlsHandshakeParser.tlsServerInformationHolder, "data/SUTServerHello");
                    }
                }
            }
        };
        try {
//            System.out.println("Entered TRY");
            int maxPackets = -1; //Non Stop ->Listening continuously
            handle.loop(maxPackets, listener);
        } catch (NotOpenException e) {
            throw new RuntimeException(e);
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        // Tell the handle to loop using the listener we create
        // Cleanup when complete
        handle.close();
    }


    private void logPacket() {
        for (int i = 0; i < TLSPacketList.size(); i++) {
            Packet currentPacket = TLSPacketList.get(i);
            String headers = PacketLogger.extractHeaders(currentPacket);
            System.out.println("Extracted Headers");
            TcpPacket tcpPacket = currentPacket.get(TcpPacket.class);
            Packet payload = tcpPacket.getPayload();

            // Log headers and raw data to file
            PacketLogger.logPacketData(headers, payload, "data/tls_handshake_data.txt");
        }
    }

    // Method to check if the payload represents a TLS Handshake record
    private boolean isTlsHandshakeRecord(Packet payload) {
        byte[] rawData = payload.getRawData();
        return rawData.length > 0 && rawData[0] == (byte) 0x16; // 0x16 indicates a TLS Handshake record
    }

    @Override
    public void startCapture() {
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


            System.out.println("Starting packet capture. Listening for TLS handshake packets on port 1234...");

            // Step 4: Start capturing packets
            captureTlsHandshakePackets(handle);

            // Step 5: Log Packets
            logPacket();

        } catch (PcapNativeException | NotOpenException e) {
            System.err.println("Error opening network interface or capturing packets: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

