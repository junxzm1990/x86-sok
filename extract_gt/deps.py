import os, sys
cur_dir = os.path.dirname(os.path.abspath(__file__))
ccr_path = os.path.abspath(os.path.join(cur_dir, '../ccr'))
proto_path = os.path.abspath(os.path.join(cur_dir, '../protobuf_def'))
sys.path.append(ccr_path)
sys.path.append(proto_path)
