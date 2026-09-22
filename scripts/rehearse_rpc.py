#!/usr/bin/env python3
"""Run repeatable local native RPC failover drills; no external traffic or funds."""
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tests'))
suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'),pattern='test_native_rehearsal.py')
result=unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps({'mode':'local HTTP providers; chain and signing fixtures','tests':result.testsRun,'passed':result.wasSuccessful(),'production_ready':False}))
sys.exit(0 if result.wasSuccessful() else 1)
