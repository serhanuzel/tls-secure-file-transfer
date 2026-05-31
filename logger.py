import os
import sys
from datetime import datetime


class LogStream:
    def __init__(self, log_folder="logs"):
        self.terminal = sys.stdout

        os.makedirs(log_folder, exist_ok=True)

        filename = datetime.now().strftime(
            f"{log_folder}/%Y-%m-%d_%H-%M-%S.log"
        )

        self.log_file = open(filename, "w", encoding="utf-8")
        self.at_line_start = True

    def write(self, message):
        if self.at_line_start:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S ")
            self.terminal.write(timestamp)
            self.log_file.write(timestamp)

        self.terminal.write(message)
        self.log_file.write(message)

        self.at_line_start = message.endswith("\n")
        self.log_file.flush()

    def flush(self):
        self.terminal.flush()
        self.log_file.flush()


def start_logging(log_folder="logs"):
    sys.stdout = LogStream(log_folder)