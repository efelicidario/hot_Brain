from flask import request, g                                                                 
from tools.logging import logger   
from neurosdk.cmn_types import * 
from flask import request
from tools.eeg import test, change_user_and_vid #on_brain_bit_signal_data_received, Sensor #comment out for mac
import os

def handle_request():
    #if g.hb == None:
    #    return ["Data Flowing"]

    #Gets the video id and user id from the request
    video_id = request.form.get('video_id')
    user_id = request.form.get('user_id')

    #changes the filename to the user_id + video_id
    name = user_id + "_" + video_id + ".pkl"
    change_user_and_vid(name)

    #if file exists, delete it to overwrite
    if os.path.exists(name):
        os.remove(name)

    #test data
    test()

    g.hb.exec_command(SensorCommand.CommandStartSignal)
    return ["Data Flowing"]