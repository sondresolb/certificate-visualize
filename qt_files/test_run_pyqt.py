import time


def run_test(process_signal):

    time.sleep(1)

    process_signal.emit(1, "Initializing analysis...")

    time.sleep(1)

    process_signal.emit(20, "one")

    time.sleep(1)

    process_signal.emit(40, "two")

    time.sleep(1)

    process_signal.emit(60, "three")

    time.sleep(1)

    process_signal.emit(80, "four")

    time.sleep(1)

    process_signal.emit(100, "five")

    time.sleep(1)
