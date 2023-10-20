from flask import request, g                                                                 
from tools.logging import logger   
from neurosdk.cmn_types import * 
from flask import request
from tools.eeg import on_brain_bit_signal_data_received, Sensor

def handle_request():
    if g.hb == None:
        return ["Data Flowing"]

    g.hb.exec_command(SensorCommand.CommandStartSignal)
    return ["Data Flowing"]