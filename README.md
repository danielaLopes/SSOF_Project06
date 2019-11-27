# Discovering vulnerabilities in Python web applications

- Executing tool:
	- $python3 ./vulnerability_detector.py <slice.json> <pattern.json>

- Example of executing tool:
	- $python3 ./vulnerability_detector.py slices/slice.json patterns/patterns.json

- Tool result:
	- The result of the vulnerability analysis are written in output JSON files inside the folder 'output/'. For example, to a file test.output.json when the program under analysis is test.json. In addition, the results are also printed on the terminal.
