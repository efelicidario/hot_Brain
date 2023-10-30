#from neurosdk.scanner import Scanner #comment out for mac
#from neurosdk.sensor import Sensor #comment out for mac
#from neurosdk.brainbit_sensor import BrainBitSensor #comment out for mac
#from neurosdk.cmn_types import *

from tools.logging import logger   
from flask import request
import pickle
import threading
import random #for testing

#doing all this a the "module level" in "Demo" server mode it will work fine :)
filename = ""
filename_lock = threading.Lock()

#will be used to store the data
pdata = []

def on_sensor_state_changed(sensor, state):
    logger.debug('Sensor {0} is {1}'.format(sensor.Name, state))

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

    pdata.append([BrainBitSignalData(PackNum=0, Marker=0, O1=-0.4, O2=-0.4000037, T3=0.4, T4=0.4), BrainBitSignalData(PackNum=0, Marker=0, O1=-0.4, O2=-0.400000389037, T3=0.387499905967, T4=0.3968326538397349)])
    pdata.append([BrainBitSignalData(PackNum=1, Marker=0, O1=-0.4, O2=-0.40000038147009037, T3=0.2790278234747157, T4=0.321679776793), BrainBitSignalData(PackNum=1, Marker=0, O1=-0.4, O2=-0.400000009037, T3=0.26652781155377536, T4=0.30917921941682763), BrainBitSignalData(PackNum=2, Marker=0, O1=-0.4, O2=-0.40000038147009037, T3=0.2049890565767828, T4=0.2390840903130439), BrainBitSignalData(PackNum=2, Marker=0, O1=-0.4, O2=-0.40000038147009037, T3=0.19248904465584246, T4=0.22658407839210357)])
    pdata.append([BrainBitSignalData(PackNum=3, Marker=0, O1=-0.3743003600123978, O2=-0.40000038147009037, T3=0.16431420702, T4=0.1933008), BrainBitSignalData(PackNum=3, Marker=0, O1=-0.3618056154785, O2=-0.40000038147009037, T3=0.15181479627112987, T4=0.1808015640273705)])