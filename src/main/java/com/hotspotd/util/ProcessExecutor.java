package com.hotspotd.util;

import java.io.BufferedReader;
import java.io.InputStreamReader;

/**
 * Utility class to execute OS-level shell commands and log them.
 * Adheres to the Single Responsibility Principle (SRP) by separating process execution from business logic.
 */
public class ProcessExecutor {

    /**
     * Executes a command, logs it, and returns the combined standard output and error output.
     * Throws an exception if the process exit code is non-zero.
     *
     * @param command The command and its arguments.
     * @return The combined process output.
     * @throws Exception If process execution fails or returns a non-zero exit code.
     */
    public String execute(String... command) throws Exception {
        String cmdString = String.join(" ", command);
        // Print to system output exactly matching the log specification format.
        System.out.printf("🔒 [FIREWALL] Executing OS Command: %s%n", cmdString);

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append(System.lineSeparator());
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException(String.format("Command failed with exit code %d: %s%nOutput: %s",
                    exitCode, cmdString, output.toString().trim()));
        }

        return output.toString();
    }

    /**
     * Executes a command, logs it, but ignores non-zero exit codes (best-effort).
     * Useful for cleanup commands that might fail if a rule has already been deleted.
     *
     * @param command The command and its arguments.
     * @return The process output, or empty string on failure.
     */
    public String executeQuietly(String... command) {
        try {
            return execute(command);
        } catch (Exception e) {
            // Log warning but do not propagate.
            System.err.printf("[WARN] Ignored failure during command: %s (%s)%n",
                    String.join(" ", command), e.getMessage().trim());
            return "";
        }
    }
}
