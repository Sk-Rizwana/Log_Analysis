import re
import csv
from collections import Counter
import os

def analyze_log_file(log_file_path, failed_login_threshold=2, csv_file_path="log_analysis_results.csv"):
    """
    Parses a log file to:
    1. Count requests per IP address.
    2. Identify the most frequently accessed endpoint.
    3. Detect suspicious IPs based on failed login attempts.
   
    Also saves the results to a CSV file.
   
    Args:
        log_file_path (str): Path to the log file.
        failed_login_threshold (int): Threshold for failed login attempts to flag suspicious IPs (default: 2).
        csv_file_path (str): Path to save the results in CSV format.
    """
    # Defining regex patterns to extract necessary data
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')  # Pattern to match IP addresses
    endpoint_pattern = re.compile(r'"(?:GET|POST|PUT|DELETE) (/[\w\-/\.]*)')  # Pattern to match API endpoints
    failed_login_pattern = re.compile(r'401|Invalid credentials')  # Pattern to detect failed login attempts

    try:
        # Opening the log file in read mode
        with open(log_file_path, 'r') as log_file:
            log_data = log_file.readlines()  # Reading all lines from the log file

        # Extracting IP addresses from each line in the log file
        ip_addresses = [ip_pattern.search(line).group() for line in log_data if ip_pattern.search(line)]
        # Extracting endpoints from each line in the log file
        endpoints = [endpoint_pattern.search(line).group(1) for line in log_data if endpoint_pattern.search(line)]
        # Extracting IPs responsible for failed logins
        failed_logins = [ip_pattern.search(line).group() for line in log_data if failed_login_pattern.search(line)]

        # Counting requests per IP address
        ip_count = Counter(ip_addresses)
        # Counting requests per endpoint
        endpoint_count = Counter(endpoints)
        # Counting failed login attempts per IP
        failed_login_count = Counter(failed_logins)

        # Identifying the most frequently accessed endpoint
        most_accessed_endpoint, max_access_count = endpoint_count.most_common(1)[0]

        # Identifying suspicious IPs with failed login attempts exceeding the threshold
        suspicious_ips = {ip: count for ip, count in failed_login_count.items() if count > failed_login_threshold}

        # Sorting IP addresses by the number of requests in descending order
        sorted_ip_count = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)

        # Printing the sorted list of IP addresses with their request counts
        print(f"{'IP Address':<20}{'Request Count':>15}")
        for ip, count in sorted_ip_count:
            print(f"{ip:<20}{count:>15}")

        # Displaying the most frequently accessed endpoint and its count
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed_endpoint} (Accessed {max_access_count} times)")

        # Printing suspicious IPs if any failed login attempts are above the threshold
        if suspicious_ips:
            print("\nSuspicious Activity Detected:")
            print(f"{'IP Address':<20}{'Failed Login Attempts':>25}")
            for ip, count in suspicious_ips.items():
                print(f"{ip:<20} {count:>25}")
        else:
            print("\nNo suspicious IPs detected.")

        # Checking if the directory for the CSV file exists
        if not os.path.exists(os.path.dirname(csv_file_path)) and os.path.dirname(csv_file_path) != '':
            print(f"Error: The directory '{os.path.dirname(csv_file_path)}' does not exist.")
            return  # Exit if directory doesn't exist

        # Writing the results to a CSV file
        with open(csv_file_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            # Writing the IP requests section
            writer.writerow(['IP Address', 'Request Count'])
            for ip, count in sorted_ip_count:
                writer.writerow([ip, count])

            writer.writerow([])  # Blank line for better readability

            # Writing the endpoint access count
            writer.writerow(['Endpoint', 'Access Count'])
            writer.writerow([most_accessed_endpoint, max_access_count])

            writer.writerow([])  # Blank line for better readability

            # Writing suspicious IPs and their failed login counts
            writer.writerow(['IP Address', 'Failed Login Count'])
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])

        # Informing the user that the results were saved successfully
        print(f"\nResults saved to {csv_file_path}")

    except FileNotFoundError:
        # Handling the case where the specified log file is not found
        print(f"Error: The file '{log_file_path}' was not found.")
    except Exception as e:
        # Handling any other exceptions and printing the error message
        print(f"An error occurred: {e}")

# Specifying the path to the log file and CSV file
log_file_path = r"D:\Git\Log_Analysis\log_file\sample_log.txt"  # Path to the log file
# Calling the function to analyze the log file
analyze_log_file(log_file_path, failed_login_threshold=2, csv_file_path=r"D:\Git\Log_Analysis\log_file\log_analysis_results.csv")
