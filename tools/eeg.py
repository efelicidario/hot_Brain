#from neurosdk.scanner import Scanner #comment out for mac
#from neurosdk.sensor import Sensor #comment out for mac
#from neurosdk.brainbit_sensor import BrainBitSensor #comment out for mac
#from neurosdk.cmn_types import *
from neurosdk.cmn_types import BrainBitSignalData
import random

from tools.logging import logger   
import threading

#doing all this a the "module level" in "Demo" server mode it will work fine :)
filename = ""
filename_lock = threading.Lock()

#will be used to store the data
pdata = []

HB_state = "Not connected yet"

def on_sensor_state_changed(sensor, state):
    global HB_state
    HB_state = state 
    logger.debug('Sensor {0} is {1}'.format(sensor.Name, state))

def get_HB_state():
    return HB_state


def on_brain_bit_signal_data_received(sensor, data):
    global filename
    global pdata
    #old method
    #data is the brainwave shid
    #with filename_lock:
    #    with open(filename, 'ab+') as f:
    #        pickle.dump(data, f)

    #new method, hopefully works
    pdata.append(data)

    logger.debug(data)

logger.debug("Create Headband Scanner")
#gl_scanner = Scanner([SensorFamily.SensorLEBrainBit]) #comment out for mac
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

#gl_scanner.sensorsChanged = sensorFound #comment out for mac

logger.debug("Start scan")
#gl_scanner.start() #comment out for mac


def get_head_band_sensor_object():
    return gl_sensor

#returns the data
def get_data():
    global pdata
    print("pdata is: " + str(pdata))
    return pdata

def clear_data():
    global pdata
    pdata = []

def change_user_and_vid(newfilename):
    global filename
    with filename_lock:
        filename = newfilename
    print("successfully changed filename to " + filename)

def test():
    #with filename_lock:
    #    with open(filename, 'ab+') as file:
    #        for i in range(0, 5):
    #            num1 = random.uniform(0, 1)
    #            num2 = random.uniform(0, 1)

    #            pickle.dump([num1, num2], file)

        #with open(filename, 'rb') as file:
        #    print("Please work: "+ pickle.load(file))
    print("test")
    global pdata

    #Appends BrainBitSignalData objects to pdata using random numbers from 0 to 1 5 times
    for i in range(0, 5):
        object_list = [BrainBitSignalData(PackNum=i, Marker=0, O1=random.uniform(0, 1), O2=random.uniform(0, 1), T3=random.uniform(0, 1), T4=random.uniform(0, 1)), 
                       BrainBitSignalData(PackNum=i, Marker=0, O1=random.uniform(0, 1), O2=random.uniform(0, 1), T3=random.uniform(0, 1), T4=random.uniform(0, 1))]
        pdata.append(object_list)