import os
import sys

# Standard entry point to run local dev server
from api.index import app

if __name__ == "__main__":
    app.run(debug=True)