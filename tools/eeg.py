from neurosdk.scanner import Scanner
from neurosdk.sensor import Sensor
from neurosdk.brainbit_sensor import BrainBitSensor
from neurosdk.cmn_types import *

from tools.logging import logger   
from flask import request
import pickle
import threading

#doing all this a the "module level" in "Demo" server mode it will work fine :)
filename = ""
filename_lock = threading.Lock()
#print("filename is " + filename)

def on_sensor_state_changed(sensor, state):
    logger.debug('Sensor {0} is {1}'.format(sensor.Name, state))

def on_brain_bit_signal_data_received(sensor, data):
    #data is the brainwave shid
    with filename_lock:
        with open(filename, 'ab+') as f:
            pickle.dump(data, f)
        logger.debug(data)

logger.debug("Create Headband Scanner")
gl_scanner = Scanner([SensorFamily.SensorLEBrainBit])
gl_sensor = None
logger.debug("Sensor Found Callback")
def sensorFound(scanner, sensors):
    global gl_scanner
    global gl_sensor
    for i in range(len(sensors)):
        logger.debug('Sensor %s' % sensors[i])
        logger.debug('Connecting to sensor')
        gl_sensor = gl_scanner.create_sensor(sensors[i])
        gl_sensor.sensorStateChanged = on_sensor_state_changed
        gl_sensor.connect()
        gl_sensor.signalDataReceived = on_brain_bit_signal_data_received
        gl_scanner.stop()
        del gl_scanner

gl_scanner.sensorsChanged = sensorFound

logger.debug("Start scan")
gl_scanner.start()


def get_head_band_sensor_object():
    return gl_sensor

def change_user_and_vid(newfilename):
    global filename
    with filename_lock:
        filename = newfilename
    print("successfully changed filename to " + filename)

def test():
    with open(filename, 'wb') as file:
        st = "this filename is: " + filename
        pickle.dump(st, file)

    with open(filename, 'rb') as file:
        print("Please work: "+ pickle.load(file))
