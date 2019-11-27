# Discovering vulnerabilities in Python web applications

- Executing tool:
	- $python3 ./vulnerability_detector.py <slice.json> <pattern.json>

- Example of executing tool:
	- $python3 ./vulnerability_detector.py slices/slice.json patterns/patterns.json

- Tool result:
	- The result of the vulnerability analysis are written in output JSON files inside the folder 'output/'. For example, to a file 'test.output.json' when the program under analysis is 'test.json'. In addition, the results are also printed on the terminal.

- Extra:
	- We made a script test.sh to test all the slices in 'slices/proj-slices/' with the given patterns file 'patterns/patterns.json'.
	- We also made new slices for testing in the 'exemplos/' and 'git_examples/' directories.
	- Also, in the 'patterns/' directory there is a file called 'patterns_BONUS.json' and it contains patterns of Path Traversal and Command Injection web vulnerabilities created by us.
