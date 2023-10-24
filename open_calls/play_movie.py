from flask import request, g                                                                 
from tools.logging import logger   
from neurosdk.cmn_types import * 
from flask import request
from tools.eeg import on_brain_bit_signal_data_received, Sensor, test, change_user_and_vid

def handle_request():
    if g.hb == None:
        return ["Data Flowing"]

    video_id = request.form.get('video_id')
    user_id = request.form.get('user_id')
    change_user_and_vid(user_id + "_" + video_id + ".pkl")

    print("video id is " + video_id)
    print("user id is " + user_id)
    test()
    g.hb.exec_command(SensorCommand.CommandStartSignal)
    return ["Data Flowing"]