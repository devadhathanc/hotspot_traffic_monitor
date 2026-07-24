package com.hotspotd.util;

/**
 * Utility class to parse IPv4 CIDR blocks and perform subnet membership checks.
 * Adheres to the Single Responsibility Principle (SRP).
 */
public class CidrBlock {
    private final int subnetIP;
    private final int mask;
    private final String originalCIDR;

    public CidrBlock(String cidr) {
        this.originalCIDR = cidr;
        String[] parts = cidr.split("/");
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid CIDR format: " + cidr);
        }

        this.subnetIP = ipToInt(parts[0]);
        int prefixLength = Integer.parseInt(parts[1]);
        if (prefixLength < 0 || prefixLength > 32) {
            throw new IllegalArgumentException("Invalid prefix length: " + prefixLength);
        }

        this.mask = prefixLength == 0 ? 0 : (0xFFFFFFFF << (32 - prefixLength));
    }

    /**
     * Checks if a given IP address string lies within this CIDR block.
     *
     * @param ipAddress String representing IPv4 address (e.g. "192.168.2.15")
     * @return true if the address is within the subnet, false otherwise.
     */
    public boolean contains(String ipAddress) {
        try {
            int ip = ipToInt(ipAddress);
            return (ip & mask) == (subnetIP & mask);
        } catch (Exception e) {
            return false;
        }
    }

    private static int ipToInt(String ipAddress) {
        String[] octets = ipAddress.split("\\.");
        if (octets.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ipAddress);
        }
        int ip = 0;
        for (int i = 0; i < 4; i++) {
            int octet = Integer.parseInt(octets[i]);
            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException("Invalid IPv4 octet: " + octet);
            }
            ip = (ip << 8) | octet;
        }
        return ip;
    }

    @Override
    public String toString() {
        return originalCIDR;
    }
}
