from flask import request, g                                                                 
from tools.logging import logger   
from neurosdk.cmn_types import * 
from tools.eeg import filename, test
import pickle

def handle_request():
    #if g.hb == None:
    #    return ["Data Flowing"]

    #opening pickled file
    with open(filename, 'rb') as file:
        data = pickle.load(file)
        print("Data is: "+ str(data))
        
    g.hb.exec_command(SensorCommand.CommandStopSignal)
    return ["Data Flowing"]

