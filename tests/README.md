# The test framework

We test the system using `pytest`. The configure file `pytest.ini` is under the root directory.

## Install pytest
```
sudo apt-get install python3-pytest
```

## Run test cases

- To run all test cases, under the root directory, execute
```
pytest # some systems name it as `pytest-3` Check the binary name in /usr/bin.
```

- To run a specific test class, under the test directory, execute
```
// -v to enable verbose
// -s to enable stdout print
pytest <test_file>::<test_class> -v
```

- To run a specific test case, under the test directory, execute
```
// -v to enable verbose
// -s to enable stdout print
pytest <test_file>::<test_class>::<test_case> -v
```

- To run the test with multiple threads
```
pytest --workers [<num>|auto]
pytest --tests-per-worker [<num>|auto]
// see more details here https://pypi.org/project/pytest-parallel/
```
