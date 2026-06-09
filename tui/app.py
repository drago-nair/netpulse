import queue
from datetime import datetime
from textual.app import App, ComposeResult
from textual.widgets import Footer, DataTable, Static
from textual.containers import Horizontal, Vertical
from rich.text import Text
from utils.alert import Alert, Severity

SEVERITY_COLORS = {
    "CRITICAL": "red",
    "HIGH": "orange3",
    "LOW": "yellow",
    "INFO": "bright_blue",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "LOW": "🟡",
    "INFO": "🔵",
}


class NetPulseTUI(App):
    CSS = """
    Screen { background: #050a0e; }

    #title {
        height: 3;
        background: #0b1318;
        border-bottom: solid #0f2a35;
        content-align: center middle;
        color: #00e5ff;
        text-style: bold;
    }

    #counters {
        height: 5;
        background: #0b1318;
        border-bottom: solid #0f2a35;
    }

    .counter {
        width: 1fr;
        height: 5;
        content-align: center middle;
        border-right: solid #0f2a35;
        text-align: center;
    }

    #alert-table { height: 1fr; }

    Footer { background: #0b1318; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "clear_table", "Clear"),
    ]

    def __init__(self, alert_queue: queue.Queue, **kwargs):
        super().__init__(**kwargs)
        self.alert_queue = alert_queue
        self._counts = {"CRITICAL": 0, "HIGH": 0, "LOW": 0, "INFO": 0}

    def compose(self) -> ComposeResult:
        yield Static("⬡  NETPULSE — LIVE NETWORK INTRUSION MONITOR", id="title")
        with Horizontal(id="counters"):
            yield Static("", id="cnt-critical", classes="counter")
            yield Static("", id="cnt-high", classes="counter")
            yield Static("", id="cnt-low", classes="counter")
            yield Static("", id="cnt-info", classes="counter")
        yield DataTable(id="alert-table", zebra_stripes=True)
        yield Footer()

    def on_mount(self):
        table = self.query_one(DataTable)
        table.add_columns("Time", "Severity", "Detector", "Source IP", "Message")
        self._update_counters()
        self.set_interval(0.3, self._drain_queue)

    def _update_counters(self):
        self.query_one("#cnt-critical").update(
            f"[bold red]{self._counts['CRITICAL']}[/]\n[dim]CRITICAL[/]"
        )
        self.query_one("#cnt-high").update(
            f"[bold orange3]{self._counts['HIGH']}[/]\n[dim]HIGH[/]"
        )
        self.query_one("#cnt-low").update(
            f"[bold yellow]{self._counts['LOW']}[/]\n[dim]LOW[/]"
        )
        self.query_one("#cnt-info").update(
            f"[bold bright_blue]{self._counts['INFO']}[/]\n[dim]INFO[/]"
        )

    def _drain_queue(self):
        try:
            while True:
                alert = self.alert_queue.get_nowait()
                self._add_alert(alert)
        except queue.Empty:
            pass

    def _add_alert(self, alert: Alert):
        sev = alert.severity.value
        color = SEVERITY_COLORS.get(sev, "white")
        emoji = SEVERITY_EMOJI.get(sev, "")
        ts = datetime.fromisoformat(alert.timestamp).strftime("%H:%M:%S")

        table = self.query_one(DataTable)
        table.add_row(
            Text(ts, style="dim"),
            Text(f"{emoji} {sev}", style=f"bold {color}"),
            Text(alert.detector, style="bright_cyan"),
            Text(alert.src_ip or "—", style="white"),
            Text(alert.message[:65], style="white"),
        )
        table.scroll_end(animate=False)

        self._counts[sev] = self._counts.get(sev, 0) + 1
        self._update_counters()

    def action_clear_table(self):
        self.query_one(DataTable).clear()
        self._counts = {"CRITICAL": 0, "HIGH": 0, "LOW": 0, "INFO": 0}
        self._update_counters()