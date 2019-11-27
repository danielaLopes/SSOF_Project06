#!/bin/bash
for VARIABLE in slices/proj-slices/*.json
do
	python3 vulnerability_detector.py $VARIABLE patterns/patterns.json
done
