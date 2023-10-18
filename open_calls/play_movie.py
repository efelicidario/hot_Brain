from flask import request, g                                                                 
from tools.logging import logger   
from neurosdk.cmn_types import * 
from flask import request
import pickle

def handle_request():
    #gets the user id and video id 
    user_id = request.form.get('user_id')
    video_id = request.form.get('video_id')

    # Create a pickle file with user ID and video ID
    data = {'user_id': user_id, 'video_id': video_id}
    with open('data.pkl', 'wb') as file:
        pickle.dump(data, file)

    if g.hb == None:
        return ["Data Flowing"]

    g.hb.exec_command(SensorCommand.CommandStartSignal)
    return ["Data Flowing"]