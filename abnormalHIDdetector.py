import time
import threading
from ctypes import windll, Structure, c_long, byref
from pywinusb import hid
from pynput import keyboard


class POINT(Structure):
    _fields_ = [("x", c_long), ("y", c_long)]


class InputSignalMonitor:
    def __init__(self, log_file="input_monitor.log"):
        self.raw_mouse_data = []
        self.desktop_mouse_data = []
        self.raw_keyboard_data = []
        self.desktop_keyboard_data = []
        self.running = False
        self.log_file = log_file

        # Initialize log file
        with open(self.log_file, "w") as file:
            file.write("Input Signal Monitor Log\n")
            file.write("=" * 50 + "\n")

    # Logging Function
    def log_difference(self, message):
        """Log the difference to the log file."""
        with open(self.log_file, "a") as file:
            file.write(message + "\n")

    # Mouse Functions
    def process_raw_mouse_signal(self, data):
        """Callback function to process raw USB mouse data."""
        timestamp = time.time()
        x_delta, y_delta = data[1], data[2]
        self.raw_mouse_data.append((timestamp, x_delta, y_delta))
        self.display_mouse_differences()

    def start_usb_mouse_monitor(self):
        """Start monitoring raw USB mouse signals."""
        devices = hid.find_all_hid_devices()
        for device in devices:
            if "mouse" in device.product_name.lower():
                mouse = device
                break
        else:
            print("No USB mouse found!")
            return

        def read_handler(data):
            self.process_raw_mouse_signal(data)

        mouse.open()
        mouse.set_raw_data_handler(read_handler)

        try:
            print("Monitoring USB mouse signals. Press Ctrl+C to stop.")
            while self.running:
                time.sleep(0.1)
        finally:
            mouse.close()

    def get_desktop_mouse_position(self):
        """Get the current position of the desktop mouse pointer."""
        pt = POINT()
        windll.user32.GetCursorPos(byref(pt))
        return pt.x, pt.y

    def start_desktop_mouse_monitor(self):
        """Start monitoring desktop mouse position."""
        last_position = self.get_desktop_mouse_position()
        while self.running:
            position = self.get_desktop_mouse_position()
            if position != last_position:
                timestamp = time.time()
                x_delta = position[0] - last_position[0]
                y_delta = position[1] - last_position[1]
                self.desktop_mouse_data.append((timestamp, x_delta, y_delta))
                last_position = position
            time.sleep(0.01)

    def display_mouse_differences(self):
        """Compare and display differences between raw USB and desktop mouse signals."""
        if not self.raw_mouse_data or not self.desktop_mouse_data:
            return

        raw_timestamp, raw_x, raw_y = self.raw_mouse_data[-1]
        desktop_timestamp, desktop_x, desktop_y = self.desktop_mouse_data[-1]

        if (raw_x, raw_y) != (desktop_x, desktop_y):
            message = (
                f"Mouse Difference detected:\n"
                f"  Raw USB Signal  - X: {raw_x}, Y: {raw_y}, Time: {raw_timestamp}\n"
                f"  Desktop Signal  - X: {desktop_x}, Y: {desktop_y}, Time: {desktop_timestamp}"
            )
            print(message)
            self.log_difference(message)

    # Keyboard Functions
    def process_raw_keyboard_signal(self, data):
        """Callback function to process raw USB keyboard data."""
        timestamp = time.time()
        self.raw_keyboard_data.append((timestamp, data))
        self.display_keyboard_differences()

    def start_usb_keyboard_monitor(self):
        """Start monitoring raw USB keyboard signals."""
        devices = hid.find_all_hid_devices()
        for device in devices:
            if "keyboard" in device.product_name.lower():
                keyboard_device = device
                break
        else:
            print("No USB keyboard found!")
            return

        def read_handler(data):
            self.process_raw_keyboard_signal(data)

        keyboard_device.open()
        keyboard_device.set_raw_data_handler(read_handler)

        try:
            print("Monitoring USB keyboard signals. Press Ctrl+C to stop.")
            while self.running:
                time.sleep(0.1)
        finally:
            keyboard_device.close()

    def on_key_press(self, key):
        """Capture desktop keyboard input."""
        timestamp = time.time()
        self.desktop_keyboard_data.append((timestamp, f"Pressed: {key}"))

    def on_key_release(self, key):
        """Capture desktop keyboard input release."""
        timestamp = time.time()
        self.desktop_keyboard_data.append((timestamp, f"Released: {key}"))

    def start_desktop_keyboard_monitor(self):
        """Start monitoring desktop keyboard input."""
        with keyboard.Listener(on_press=self.on_key_press, on_release=self.on_key_release) as listener:
            listener.join()

    def display_keyboard_differences(self):
        """Compare and display differences between raw USB and desktop keyboard signals."""
        if not self.raw_keyboard_data or not self.desktop_keyboard_data:
            return

        raw_timestamp, raw_data = self.raw_keyboard_data[-1]
        desktop_timestamp, desktop_data = self.desktop_keyboard_data[-1]

        if raw_data != desktop_data:
            message = (
                f"Keyboard Difference detected:\n"
                f"  Raw USB Signal  - Data: {raw_data}, Time: {raw_timestamp}\n"
                f"  Desktop Signal  - Data: {desktop_data}, Time: {desktop_timestamp}"
            )
            print(message)
            self.log_difference(message)

    # Main Functions
    def start(self):
        """Start all monitors in separate threads."""
        self.running = True

        mouse_usb_thread = threading.Thread(target=self.start_usb_mouse_monitor, daemon=True)
        mouse_desktop_thread = threading.Thread(target=self.start_desktop_mouse_monitor, daemon=True)
        keyboard_usb_thread = threading.Thread(target=self.start_usb_keyboard_monitor, daemon=True)
        keyboard_desktop_thread = threading.Thread(target=self.start_desktop_keyboard_monitor, daemon=True)

        mouse_usb_thread.start()
        mouse_desktop_thread.start()
        keyboard_usb_thread.start()
        keyboard_desktop_thread.start()

        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.running = False
            print("Stopping monitoring...")

        mouse_usb_thread.join()
        mouse_desktop_thread.join()
        keyboard_usb_thread.join()
        keyboard_desktop_thread.join()


if __name__ == "__main__":
    monitor = InputSignalMonitor()
    monitor.start()
