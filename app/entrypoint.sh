#!/bin/bash
flask init-db
exec gunicorn -b 0.0.0.0:5000 app:app