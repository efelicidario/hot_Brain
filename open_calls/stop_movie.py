from flask import request, g                                                                 
from tools.logging import logger   
from neurosdk.cmn_types import * 
from tools.eeg import filename, test, get_data, clear_data #on_brain_bit_signal_data_received, Sensor #comment out for mac
import pickle
import os

def handle_request():

    #if g.hb == None:
    #    return ["Data Flowing"]

    video_id = request.form.get('video_id')
    user_id = request.form.get('user_id')

    filename = user_id + "_" + video_id + ".pkl"


    #old method
    #opening pickled file
    #with open(filename, 'rb') as file:
    #    data = pickle.load(file)
    #    print("Data is: "+ str(data))

    #new method, hopefully works
    #g.hb.exec_command(SensorCommand.CommandStopSignal) #comment out for mac

    #data goes here
    data_folder = "data/"

    #path
    name = os.path.join(data_folder, filename)

    #Check if folder exists, if not, create it
    if not os.path.exists(data_folder):
        os.makedirs(data_folder)

    #if file exists, delete it to overwrite
    if os.path.exists(name):
        os.remove(name)

    #gets and pickles data
    thedata = get_data()
    with open(name, 'wb') as file:
        pickle.dump(thedata, file)

    #see if it works
    with open(name, 'rb') as file:
        data = pickle.load(file)
        print("Data is: "+ str(data))

    #now delete the data from the global variable
    clear_data()

    return ["Data Flowing"]

