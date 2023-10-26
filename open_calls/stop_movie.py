from flask import request, g                                                                 
from tools.logging import logger   
from neurosdk.cmn_types import * 
from tools.eeg import filename, test, get_data, clear_data #on_brain_bit_signal_data_received, Sensor #comment out for mac
import pickle

def handle_request():

    #if g.hb == None:
    #    return ["Data Flowing"]

    #old method
    #opening pickled file
    #with open(filename, 'rb') as file:
    #    data = pickle.load(file)
    #    print("Data is: "+ str(data))
       


    #new method, hopefully works
    #g.hb.exec_command(SensorCommand.CommandStopSignal)

    #gets and pickles data
    thedata = get_data()
    with open(filename, 'wb') as file:
        pickle.dump(thedata, file)

    #see if it works
    with open(filename, 'rb') as file:
        data = pickle.load(file)
        print("Data is: "+ str(data))

    #now delete the data from the global variable
    clear_data()

    return ["Data Flowing"]

