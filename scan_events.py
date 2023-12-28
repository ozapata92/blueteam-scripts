import win32evtlog
from colorama import Fore, Style, init
import time


class WindowsEventLogReader:
    def __init__(self):
        self.eventos = {
            "Create Services": [7030, 7045],
            # "Command Line Auditing": [4688],
            "Create User": [4720, 4722, 4724, 4728],
            "Add User to Group": [4732],
            "Clear Event Log": [1102],
            "Create RDP Certificate": [1056],
            "Insert USB": [7045, 10000, 10001, 10100, 20001, 20002, 20003, 24576, 24577, 24579],
            "Disable Firewall": [2003],
            "Applocker": [8003, 8004, 8006, 8007],
            "EMET": [2],
            # "Logon Success": [4624],
            "Logon Failed": [4625],
            "service terminated unexpectedly": [7034],
            "A service was installed in the system": [4697],
            "User Account Locked Out": [4740],
            "User Account Unlocked Out": [4767],
            "File Access / Deletion": [4663, 4659, 4660],
            "Terminal service session reconnected": [4778],
            "Terminal service session disconnected": [4779],
            "User Initiated Logoff": [4647],
            "A directory service object was created": [5137],
            "A directory service object was modified": [5136],
            "Permission change with old & new attributes": [4670],
            "Service Start Type Change (disabled, manual. Automatic)": [7040],
            "Service Start / Stop": [7036]
        }
        self.logType = "Security"
        self.hand = None

    def connect_event_log(self):
        self.hand = win32evtlog.OpenEventLog(None, self.logType)

    def disconnect_event_log(self):
        if self.hand:
            win32evtlog.CloseEventLog(self.hand)

    def read_events(self):
        init(autoreset=True)  # Inicializar colorama

        while True:
            events = win32evtlog.ReadEventLog(self.hand, win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ, 0)
            if events:
                for event in events:
                    for tipo, ids in self.eventos.items():
                        if event.EventID in ids:
                            print(f"Tipo de Evento: {Fore.BLUE}{tipo}{Style.RESET_ALL}, ID: {Fore.RED}{event.EventID}{Style.RESET_ALL}, Hora: {Fore.GREEN}{event.TimeGenerated}{Style.RESET_ALL}")
                            time.sleep(0.5)  # Agregar un timeout de 0.5 segundos entre eventos

if __name__ == "__main__":
    event_log_reader = WindowsEventLogReader()
    event_log_reader.connect_event_log()
    event_log_reader.read_events()
    event_log_reader.disconnect_event_log()
