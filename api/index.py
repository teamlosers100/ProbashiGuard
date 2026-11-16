import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from mangum import Mangum
from app import app as fastapi_app

handler = Mangum(fastapi_app, lifespan="off")
