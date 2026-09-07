import json
# Path to the Cowrie log file
log_file = "logs/cowrie.json"
# Open the file
with open(log_file, "r", encoding="utf-8") as file:

    # Read only the first line
    first_line = file.readline()

    print(first_line)