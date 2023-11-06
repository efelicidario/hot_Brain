from flask import request, g                                                                 
from tools.logging import logger   
from neurosdk.cmn_types import * 
from tools.eeg import test, change_user_and_vid #on_brain_bit_signal_data_received, Sensor #comment out for mac

def handle_request():
    #if g.hb == None:
    #    return ["Data Flowing"]

    #Gets the video id and user id from the request
    video_id = request.form.get('video_id')
    user_id = request.form.get('user_id')

    #gets the filename
    name = user_id + "_" + video_id + ".pkl"

    #test data comment out for real thing
    test()

    g.hb.exec_command(SensorCommand.CommandStartSignal)
    return ["Data Flowing"]